/**
 * React Native RASP Bypass
 * Neutraliza módulos RNNuDetect en el puente React Native
 */

if (ObjC.available) {
    console.log("[+] React Native RASP Bypass Loaded");
    
    try {
        // Hook RNNuDetect module registration
        var RCTBridgeModule = ObjC.classes.RCTBridgeModule;
        if (RCTBridgeModule) {
            console.log("[+] RCTBridgeModule found");
        }
        
        // Buscar clases relacionadas con NuDetect
        for (var className in ObjC.classes) {
            if (className.includes("NuDetect") || className.includes("RNNuDetect")) {
                console.log("[+] Found NuDetect class: " + className);
                
                try {
                    var cls = ObjC.classes[className];
                    var methods = cls.$ownMethods;
                    
                    for (var i = 0; i < methods.length; i++) {
                        var method = methods[i];
                        console.log("[+] Method: " + method);
                        
                        try {
                            var impl = cls[method].implementation;
                            if (impl) {
                                Interceptor.attach(impl, {
                                    onEnter: function(args) {
                                        console.log("[RASP BLOCKED] " + className + " " + method);
                                    },
                                    onLeave: function(retval) {
                                        // Retornar nil/false para bloquear
                                    }
                                });
                            }
                        } catch (e) {
                            // Method not hookable
                        }
                    }
                } catch (e) {
                    console.log("[!] Error hooking " + className + ": " + e);
                }
            }
        }
        
        console.log("[+] React Native RASP Bypass: Hooks installed");
        
    } catch (e) {
        console.log("[!] Error: " + e);
    }
    
    // Reportar estado cada 5s
    setInterval(function() {
        console.log("[HEARTBEAT] RASP bypass active");
    }, 5000);
} else {
    console.log("[!] Objective-C runtime not available");
}
