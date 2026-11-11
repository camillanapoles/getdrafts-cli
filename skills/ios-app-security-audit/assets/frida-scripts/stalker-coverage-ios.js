/**
 * Stalker Coverage Collection for iOS
 *
 * This script uses Frida's Stalker to collect code coverage information.
 * It tracks which basic blocks have been executed during runtime.
 *
 * Use cases:
 * - Fuzzing: Track code coverage during fuzzing campaigns
 * - Anti-cheat research: Understand which code paths are monitored
 * - Reverse engineering: Identify executed functions during specific workflows
 * - Testing: Verify test coverage
 *
 * Usage:
 *   frida -U -f com.example.app -l stalker-coverage-ios.js
 *   frida -U -p <PID> -l stalker-coverage-ios.js
 *
 * iOS Simulator:
 *   frida -D <UDID> -p <PID> -l stalker-coverage-ios.js
 */

console.log("[*] Stalker Coverage Collection loaded");
const config = {
    // Stalker events to collect
    events: {
        compile: true,    // Track newly compiled blocks
        block: true,      // Track block execution
        call: false,      // Track function calls (verbose)
        ret: false,       // Track returns (verbose)
        exec: false,      // Track instruction execution (very verbose)
    },

    // Output format: 'json', 'text', or 'both'
    output_format: 'text',

    // Print coverage interval (ms)
    print_interval: 5000,
    };
const coverage = {
    blocks: new Map(),
    functions: new Map(),
    modules: new Map(),
    total_blocks: 0,
    start_time: Date.now(),
};

const activeStalkers = new Map();

setTimeout(function() {
    if (ObjC.available) {
        console.log("[*] Objective-C runtime available");
        console.log("[*] Usage: startStasher(tid) to begin coverage");
        console.log("[*] Usage: stopStasher(tid) to end coverage");
        console.log("[*] Usage: printCoverage() to show results");
    } else {
        console.log("[!] Objective-C runtime not available");
    }
}, 100);

function startStasher(tid, options) {
    try {
        const threadId = tid || Process.getCurrentThread().id;
        console.log("[*] Starting Stalker for thread:", threadId);

        const opts = Object.assign({}, config.events, options);
        let event_mask = 0;
        if (opts.compile) event_mask |= Stalker.EVENT.COMPILE;
        if (opts.block) event_mask |= Stalker.EVENT.BLOCK;
        if (opts.call) event_mask |= Stalker.EVENT.CALL;
        if (opts.ret) event_mask |= Stalker.EVENT.RET;
        if (opts.exec) event_mask |= Stalker.EVENT.EXEC;

        Stalker.follow(threadId, {
            events: event_mask,

            transform: function(iterator) {
                const iterator_ptr = new NativePointer(iterator);

                while (iterator_ptr.toInt32() !== 0) {
                    const block = iterator_ptr.readPointer();

                    const module = Process.findModuleByAddress(block);
                    const moduleName = module ? module.name : 'unknown';
                    const offset = module ? block.sub(module.base) : block;

                    recordBlock(block, moduleName, offset);

                    iterator_ptr = iterator_ptr.add(Process.pointerSize);
                }
            },

            onReceive: function(events) {
                if (opts.compile || opts.block) {
                    parseEvents(events);
                }
            },

            onComplete: function() {
                console.log("[*] Stalker completed for thread:", threadId);
            }
        });

        activeStalkers.set(threadId, true);
        console.log("[*] Stalker started successfully");

    } catch (e) {
        console.log("[!] Failed to start Stalker:", e);
    }
    }
function stopStasher(tid) {
    try {
        const threadId = tid || Process.getCurrentThread().id;

        if (activeStalkers.has(threadId)) {
            Stalker.unfollow(threadId);
            activeStalkers.delete(threadId);
            console.log("[*] Stalker stopped for thread:", threadId);
        } else {
            console.log("[!] No active Stalker for thread:", threadId);
        }
    } catch (e) {
        console.log("[!] Failed to stop Stalker:", e);
    }
    }
function stopAllStashers() {
    console.log("[*] Stopping all active stalkers...");

    for (const tid of activeStalkers.keys()) {
        stopStasher(tid);
    }

    console.log("[*] All stalkers stopped");
    }

function recordBlock(address, moduleName, offset) {
    const addr_str = address.toString();

    coverage.blocks.set(addr_str, (coverage.blocks.get(addr_str) || 0) + 1);
    coverage.total_blocks++;

    coverage.modules.set(moduleName, (coverage.modules.get(moduleName) || 0) + 1);
    }

function parseEvents(events) {
    const iterator = Stalker.parse(events);

    for (const event of iterator) {
        if (event[0] === 'block') {
            const address = event[1];
            const module = Process.findModuleByAddress(address);
            const moduleName = module ? module.name : 'unknown';
            const offset = module ? address.sub(module.base) : address;

            recordBlock(address, moduleName, offset);
        }
    }
    }

function printCoverage() {
    const elapsed = Date.now() - coverage.start_time;
    const elapsed_sec = elapsed / 1000;

    console.log("\n[*] ===== Coverage Summary =====");
    console.log("[*] Elapsed time:", elapsed_sec.toFixed(2), "seconds");
    console.log("[*] Total blocks executed:", coverage.total_blocks);
    console.log("[*] Unique blocks:", coverage.blocks.size);
    console.log("[*] Modules covered:", coverage.modules.size);

    console.log("\n[*] ----- Coverage by Module -----");
    for (const [moduleName, count] of coverage.modules) {
        console.log(`  ${moduleName}: ${count} blocks`);
    }

    console.log("\n[*] ----- Most Executed Blocks -----");
    const sortedBlocks = Array.from(coverage.blocks.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    for (const [addr, count] of sortedBlocks) {
        const address = ptr(addr);
        const module = Process.findModuleByAddress(address);
        const moduleName = module ? module.name : 'unknown';
        const offset = module ? address.sub(module.base) : address;
        const symbol = module ? module.findSymbolByAddress(offset, true) : null;

        console.log(`  ${addr} (${moduleName}): ${count} hits`);
        if (symbol) {
            console.log(`    Symbol: ${symbol.name}`);
        }
    }

    console.log("[*] ===== End of Summary =====\n");
    }

function exportCoverage() {
    const elapsed = Date.now() - coverage.start_time;

    return JSON.stringify({
        metadata: {
            elapsed_time_ms: elapsed,
            total_blocks: coverage.total_blocks,
            unique_blocks: coverage.blocks.size,
            modules_count: coverage.modules.size,
            timestamp: new Date().toISOString(),
        },
        blocks: Object.fromEntries(coverage.blocks),
        modules: Object.fromEntries(coverage.modules),
    }, null, 2);
    }

function saveCoverage(filename) {
    const fname = filename || 'frida_coverage.json';

    try {
        const data = exportCoverage();
        const file = new File(fname, 'w');
        file.write(data);
        file.close();
        console.log("[*] Coverage saved to:", fname);
    } catch (e) {
        console.log("[!] Failed to save coverage:", e);
    }
    }
if (config.print_interval > 0) {
    setInterval(function() {
        if (coverage.total_blocks > 0) {
            console.log("\n[*] === Periodic Coverage Update ===");
            console.log("[*] Total blocks:", coverage.total_blocks);
            console.log("[*] Unique blocks:", coverage.blocks.size);
            console.log("[*] Active threads:", activeStalkers.size);
        }
    }, config.print_interval);
    }

function autoStartOnMethod(className, methodName) {
    try {
        const clazz = ObjC.classes[className];
        if (!clazz) {
            console.log("[!] Class not found:", className);
            return;
        }

        const method = clazz[methodName];
        if (!method) {
            console.log("[!] Method not found:", methodName);
            return;
        }

        console.log("[*] Setting up auto-start for", className, methodName);

        Interceptor.attach(method, {
            onEnter: function(args) {
                const tid = Process.getCurrentThread().id;
                if (!activeStalkers.has(tid)) {
                    console.log("[*] Auto-starting Stalker on method call");
                    startStasher(tid);
                }
            },
            onLeave: function(retval) {
                // Optional: print coverage when method returns
                // printCoverage();
            }
        });
    } catch (e) {
        console.log("[!] Failed to set up auto-start:", e);
    }
    }
// setTimeout(function() {
//     console.log("[*] Auto-starting Stalker on main thread");
//     startStasher(Process.getCurrentThread().id);
// }, 2000);
rpc.exports = {
    start: startStasher,
    stop: stopStasher,
    stopAll: stopAllStashers,
    print: printCoverage,
    export: exportCoverage,
    save: saveCoverage,
    autoStartOnMethod: autoStartOnMethod,
};

console.log("[*] Stalker Coverage Collection - Ready");
console.log("[*] Available RPC functions:");
console.log("[*]   .start(tid) - Start coverage for thread");
console.log("[*]   .stop(tid) - Stop coverage for thread");
console.log("[*]   .stopAll() - Stop all coverage");
console.log("[*]   .print() - Print coverage summary");
console.log("[*]   .export() - Export coverage as JSON");
console.log("[*]   .save(filename) - Save coverage to file");
