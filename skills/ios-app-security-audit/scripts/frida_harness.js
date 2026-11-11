#!/usr/bin/env node
/**
 * Carga cada script de assets/frida-scripts/ bajo un API de Frida simulado y
 * reporta los errores en tiempo de ejecucion.
 *
 * `node --check` solo valida la sintaxis. Un script puede analisar sin
 * problemas y fallar en cuanto se carga: una referencia a una funcion que no
 * existe, un metodo de Objective-C llamado sobre un puntero crudo, un
 * `ObjC.classes.forEach` sobre algo que no es un array.
 *
 * El source se evalua como una FUNCION, igual que hace Frida
 * (JS_EvalFunction sobre un entrypoint que es un valor de funcion), de modo
 * que un `return` de primer nivel es valido.
 *
 * Uso:  node scripts/frida_harness.js [directorio]
 * Salida: 0 si todos los scripts cargan, 1 si alguno falla.
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const DIR = process.argv[2] || path.join(process.cwd(), "assets/frida-scripts");

// --------------------------------------------------------------------- mock

function makeAnything(label) {
  const target = function () {};
  target.__label = label;
  return new Proxy(target, {
    get(t, prop) {
      if (prop === Symbol.toPrimitive) return () => 0;
      if (prop === Symbol.iterator) return undefined;
      if (prop === "toString") return () => label;
      if (prop === "valueOf") return () => 0;
      if (prop === "inspect") return () => label;
      if (typeof prop === "symbol") return undefined;
      if (prop === "isNull") return () => false;
      if (prop === "toInt32") return () => 0;
      if (prop === "toUInt32") return () => 0;
      if (prop === "toInt64") return () => 0n;
      if (prop === "toString") return () => label;
      if (prop === "toPointer") return () => makeAnything("ptr");
      if (prop === "add") return () => makeAnything("ptr+");
      if (prop === "sub") return () => makeAnything("ptr-");
      if (prop === "readPointer") return () => makeAnything("ptr");
      if (prop === "readU8" || prop === "readU16" || prop === "readU32" || prop === "readS32" || prop === "readByteArray" || prop === "readFloat") return () => new Uint8Array(8);
      if (prop === "readUtf8String") return () => label;
      if (prop === "readUtf16String") return () => label;
      if (prop === "writePointer" || prop === "writeU8" || prop === "writeU16" || prop === "writeU32" || prop === "writeS32" || prop === "writeInt32" || prop === "writeUtf8String" || prop === "writeByteArray" || prop === "writeFloat" || prop === "writeS8") return () => 0;
      if (prop === "equals") return () => false;
      if (prop === "compare") return () => 0;
      if (prop === "sign") return () => 1;
      if (prop === "and" || prop === "or" || prop === "xor" || prop === "shl" || prop === "shr") return () => makeAnything("ptr?");
      if (prop === "not") return () => makeAnything("ptr~");
      if (prop === "implementation") return makeAnything("impl");
      if (prop === "returnType") return "bool";
      if (prop === "argumentTypes") return [];
      if (prop === "name") return label;
      if (prop === "path") return label;
      if (prop === "base") return makeAnything("base");
      if (prop === "size") return 4096;
      if (prop === "isNull") return () => false;
      if (prop === "enumerateExports" || prop === "enumerateSymbols" || prop === "enumerateRanges" || prop === "enumerateMethods" || prop === "enumerate") return () => [];
      if (prop === "then") return undefined;
      return makeAnything(label + "." + String(prop));
    },
    apply(t, thisArg, args) {
      return makeAnything(label + "()");
    },
  });
}

const CLASS_NAMES = [
  "NSObject", "NSString", "NSURL", "NSURLSession", "NSURLSessionTask",
  "NSMutableURLRequest", "NSData", "NSMutableData", "NSBundle", "NSUserDefaults",
  "NSFileManager", "NSProcessInfo", "NSTimer", "NSThread", "NSNotificationCenter",
  "UIApplication", "UIDevice", "UIPasteboard", "UIActivityViewController",
  "UIWebView", "WKWebView", "NSURLProtectionSpace", "NSURLCredential",
  "SecTrustEvaluate", "CFNetworkCopySystemProxySettings", "SecItemAdd",
];

// ObjC.classes es un MAP, no un array: no tiene forEach (el bug clasico).
const objcClasses = new Proxy(
  {},
  {
    get(t, prop) {
      if (prop === "forEach" || prop === "map" || prop === "filter" || prop === "length") return undefined;
      if (typeof prop === "symbol") return undefined;
      // En Frida, ObjC.classes["lo que sea"] es undefined si no es el nombre
      // de una clase cargada. Reproducirlo es lo que permite detectar
      // "ObjC.classes[undefined]" (un lookup sobre un valor mal resuelto).
      if (typeof prop !== "string" || !/^[A-Z]/.test(prop)) return undefined;
      if (CLASS_NAMES.includes(prop)) return makeClass(prop);
      return makeClass(String(prop));
    },
    has() { return true; },
    ownKeys() { return CLASS_NAMES.slice(); },
    getOwnPropertyDescriptor() { return { enumerable: true, configurable: true }; },
  }
);

function makeClass(name) {
  const c = makeAnything("class " + name);
  return new Proxy(c, {
    get(t, prop) {
      // En Frida la jerarquia termina: superclass acaba en null.
      if (prop === "superclass") return null;
      if (prop === "$superclass") return null;
      if (prop === "$superClass") return null;
      return Reflect.get(t, prop);
    },
  });
}

const objcProtocols = new Proxy(
  {},
  {
    get(t, prop) {
      if (typeof prop === "symbol") return undefined;
      return { methods: {}, properties: {} };
    },
    has() { return true; },
  }
);

function ObjCObject(ptr) {
  return new Proxy(
    {},
    {
      get(t, prop) {
        if (prop === Symbol.toPrimitive) return () => 0;
        if (prop === "toString") return () => "ObjCObject";
        if (prop === "valueOf") return () => 0;
        if (prop === "isNull") return () => false;
        if (prop === "absoluteString") return () => makeAnything("nsurl");
        if (prop === "$className") return "MockClass";
        if (prop === "$class") return makeClass("MockClass");
        if (prop === "$kind") return "instance";
        if (prop === "$moduleName") return "MockModule";
        if (prop === "respondsToSelector") return () => true;
        if (prop === "conformsToProtocol") return () => false;
        if (typeof prop === "symbol") return undefined;
        // El bridge devuelve un WRAPPER DE METODO (una funcion) para cualquier
        // selector; el valor solo existe al invocarlo. Sin esta regla, un
        // "app.delegate" sin parentesis devolveria un objeto y el bug pasaria
        // desapercibido.
        const wrapper = function () { return ObjCObject(ptr); };
        wrapper.implementation = makeAnything("impl");
        return wrapper;
      },
      apply() { return ObjCObject(ptr); },
    }
  );
}

function makeModule(name) {
  return {
    name,
    path: "/mock/" + name,
    base: makeAnything("base"),
    size: 4096,
    getExportByName: () => makeAnything("export"),
    findExportByName: () => makeAnything("export"),
    getFunctionByName: () => makeAnything("fn"),
    findFunctionByName: () => makeAnything("fn"),
    enumerateExports: () => [],
    enumerateSymbols: () => [],
    enumerateRanges: () => [],
    getRangeByAddress: () => null,
  };
}

function makeContext() {
  const deferred = [];
  const Module = {
    load: () => makeModule("mock.dylib"),
    getGlobalExportByName: () => makeAnything("globalExport"),
    findGlobalExportByName: () => makeAnything("globalExport"),
    enumerateExports: () => [],
    enumerateSymbols: () => [],
    enumerateRanges: () => [],
    getBaseAddress: () => makeAnything("base"),
  };

  const Process = {
    arch: "arm64",
    platform: "ios",
    pageSize: 4096,
    pointerSize: 8,
    id: 1234,
    enumerateModules: () => [makeModule("mock.dylib")],
    findModuleByName: () => makeModule("mock.dylib"),
    getModuleByName: () => makeModule("mock.dylib"),
    findModuleByAddress: () => makeModule("mock.dylib"),
    getModuleByAddress: () => makeModule("mock.dylib"),
    enumerateThreads: () => [],
    enumerateRanges: () => [],
    getCurrentThreadId: () => 1,
    mainModule: makeModule("mock.dylib"),
  };

  const ctx = {
    console: {
      log: () => {},
      warn: () => {},
      error: () => {},
      info: () => {},
      debug: () => {},
    },
    print: () => {},
    Module,
    Process,
    ObjC: {
      available: true,
      classes: objcClasses,
      protocols: objcProtocols,
      Object: ObjCObject,
      selector: (s) => String(s),
      methodSignature: () => "v@:",
      api: {},
      allocate: (s) => makeAnything("objcstr"),
      alloc: (s) => makeAnything("objcstr"),
      mainQueue: { name: "main" },
      schedule: function (a, b) {
        // ObjC.schedule(fn) u ObjC.schedule(queue, fn)
        const fn = typeof a === "function" ? a : b;
        if (typeof fn === "function") deferred.push(fn);
        return 0;
      },
      ensure: (cls) => makeAnything("ensure"),
      dealloc: (p) => {},
      register: (p) => {},
    },
    Interceptor: {
      attach: () => ({ detach: () => {} }),
      replace: () => ({ revert: () => {} }),
      detach: () => {},
      flush: () => {},
    },
    NativeFunction: function (address, retType, argTypes) {
      const f = function () { return makeAnything("native"); };
      f.toString = () => "NativeFunction";
      return f;
    },
    NativeCallback: function (fn) {
      const f = function () { return undefined; };
      f.toString = () => "NativeCallback";
      return f;
    },
    Memory: {
      alloc: () => makeAnything("mem"),
      allocUtf8String: () => makeAnything("memstr"),
      allocUtf16String: () => makeAnything("memstr16"),
      protect: () => makeAnything("mem"),
      scan: () => [],
      readByteArray: () => new Uint8Array(8),
    },
    NativePointer: function (v) { return makeAnything("ptr"); },
    NativePointerValue: function (v) { return makeAnything("npv"); },
    Int64: function (v) { return makeAnything("i64"); },
    UInt64: function (v) { return makeAnything("u64"); },
    ArrayBuffer: ArrayBuffer,
    Uint8Array: Uint8Array,
    DataView: DataView,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder,
    Buffer: Buffer,
    setImmediate: (fn) => { deferred.push(fn); return 0; },
    setTimeout: (fn) => { deferred.push(fn); return 0; },
    setInterval: () => 0,
    clearTimeout: () => {},
    clearInterval: () => {},
    clearImmediate: () => {},
    send: () => {},
    recv: () => {},
    Script: { new: () => ({ load: () => {} }) },
    Java: undefined,
    Socket: undefined,
    File: undefined,
    SocketIO: undefined,
    rpc: { export: () => {} },
    _deferred: deferred,
  };
  ctx.global = ctx;
  ctx.globalThis = ctx;
  return ctx;
}

// ------------------------------------------------------------------- runner

function loadScript(file) {
  const code = fs.readFileSync(file, "utf8");
  const ctx = makeContext();
  const errors = [];
  const notes = [];
  const sandbox = vm.createContext(ctx);

  // Los scripts usan console.log de Frida; se captura para detectar
  // "Error" en la salida, que es como Frida reporta un fallo de hook.
  const captured = [];
  ctx.console = {
    log: (...a) => captured.push(a.map(String).join(" ")),
    warn: (...a) => captured.push("WARN " + a.map(String).join(" ")),
    error: (...a) => captured.push("ERROR " + a.map(String).join(" ")),
    info: (...a) => captured.push(a.map(String).join(" ")),
    debug: () => {},
  };

  try {
    vm.runInContext(code, sandbox, { filename: file, timeout: 5000 });
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    // Frida evalua el source como una FUNCION (JS_EvalFunction sobre un
    // entrypoint que es un valor de funcion), no como un programa. Si el
    // script solo funciona envuelto, en Frida tambien funciona.
    if (/Illegal return statement|return statement/i.test(msg)) {
      try {
        vm.runInContext("(function(){\n" + code + "\n})()", sandbox, { filename: file, timeout: 5000 });
        notes.push(file + ": solo carga con el source envuelto en una funcion (modo funcion de Frida, que es el suyo)");
        return { errors, captured, notes };
      } catch (e2) {
        errors.push("carga: " + (e2 && e2.stack ? e2.stack.split("\n").slice(0, 3).join(" | ") : String(e2)));
        return { errors, captured, notes };
      }
    }
    errors.push("carga: " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join(" | ") : String(e)));
    return { errors, captured, notes };
  }

  // Ejecutar los callbacks diferidos (setImmediate / setTimeout)
  for (let i = 0; i < ctx._deferred.length && i < 20; i++) {
    try {
      ctx._deferred[i]();
    } catch (e) {
      errors.push("diferido: " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join(" | ") : String(e)));
    }
  }
  return { errors, captured, notes };
}

// --------------------------------------------------------------------- main

const files = fs.readdirSync(DIR).filter((f) => f.endsWith(".js")).sort();
let ok = 0;
const failures = [];
const allNotes = [];

for (const f of files) {
  const file = path.join(DIR, f);
  let res;
  try {
    res = loadScript(file);
  } catch (e) {
    res = { errors: ["harness: " + e], captured: [] };
  }
  for (const n of res.notes || []) allNotes.push(n);
  if (res.errors.length === 0) {
    ok++;
  } else {
    failures.push({ file: f, errors: res.errors });
  }
}

console.log("=".repeat(74));
console.log("CARGA DE SCRIPTS FRIDA BAJO API SIMULADO");
console.log("=".repeat(74));
for (const fail of failures) {
  console.log("\nFAIL  " + fail.file);
  for (const e of fail.errors) console.log("      " + e);
}
if (allNotes.length) {
  console.log("\nNOTAS (no son fallos):");
  for (const n of allNotes) console.log("  - " + n);
}
console.log("\n" + "-".repeat(74));
console.log(`${ok}/${files.length} scripts se cargan sin error`);
process.exit(failures.length ? 1 : 0);
