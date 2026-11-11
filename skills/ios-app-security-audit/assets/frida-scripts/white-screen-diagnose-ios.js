/**
 * Frida script para diagnosticar pantalla blanca en iOS app
 *
 * Busca:
 * 1. Si la UIWindow está visible
 * 2. Si hay UIViewController activo
 * 3. Si el rootViewController está seteado
 * 4. Si hay algo en la vista principal
 * 5. Si la app está en foreground/background
 */

console.log("[*] White Screen Diagnose - Starting...");

if (ObjC.available) {
    console.log("[+] ObjC runtime available");

    // Some shared helpers expect a Java bridge. iOS has no Java VM, so the
    // global does not exist at all: assigning to it aborted the whole script
    // at load time with "Cannot set properties of undefined".
    if (typeof Java !== 'undefined') {
        Java.perform = function() {};
    }

    try {
        // Hook UIApplication lifecycle
        var UIApplication = ObjC.classes.UIApplication;
        if (UIApplication) {
            console.log("[+] Found UIApplication class");

            // Check app state
            var app = UIApplication.sharedApplication();
            if (app) {
                var state = app.applicationState();
                console.log("[*] App state: " + state + " (0=Active, 1=Inactive, 2=Background)");

                // Check key window
                var keyWindow = app.keyWindow();
                if (keyWindow) {
                    console.log("[+] Key window exists!");
                    console.log("[*] Key window: " + keyWindow);

                    // Check rootViewController
                    var rootVC = keyWindow.rootViewController();
                    if (rootVC) {
                        console.log("[+] RootViewController: " + rootVC);
                        console.log("[*] RootVC class: " + rootVC.$className);

                        // Check if view is loaded
                        var view = rootVC.view();
                        if (view) {
                            console.log("[+] RootVC view exists!");
                            console.log("[*] View frame: " + view.frame());
                            console.log("[*] View hidden: " + view.isHidden());
                            console.log("[*] View alpha: " + view.alpha());
                            console.log("[*] View subviews count: " + view.subviews().count());

                            // List subviews
                            var subviews = view.subviews();
                            for (var i = 0; i < Math.min(5, subviews.count()); i++) {
                                console.log("[*] Subview " + i + ": " + subviews.objectAtIndex_(i).$className);
                            }
                        } else {
                            console.log("[-] RootVC view is nil!");
                        }
                    } else {
                        console.log("[-] NO RootViewController - this explains white screen!");
                    }

                    // Check all windows
                    var windows = app.windows();
                    console.log("[*] Total windows: " + windows.count());

                    for (var i = 0; i < windows.count(); i++) {
                        var win = windows.objectAtIndex_(i);
                        console.log("[*] Window " + i + ": " + win.$className + " hidden=" + win.isHidden());
                    }
                } else {
                    console.log("[-] NO Key Window - app not fully initialized!");
                }
            }
        }

        // Hook viewDidLoad to see if ViewControllers are loading
        var UIViewController = ObjC.classes.UIViewController;
        if (UIViewController) {
            var viewDidLoad = UIViewController['- viewDidLoad'];
            if (viewDidLoad) {
                Interceptor.attach(viewDidLoad.implementation, {
                    onEnter: function(args) {
                        var vc = ObjC.Object(args[0]);
                        console.log("[*] viewDidLoad called: " + vc.$className);
                    }
                });
            }
        }

        // Hook makeKeyAndVisible
        var UIWindow = ObjC.classes.UIWindow;
        if (UIWindow) {
            var makeKey = UIWindow['- makeKeyAndVisible'];
            if (makeKey) {
                Interceptor.attach(makeKey.implementation, {
                    onEnter: function(args) {
                        var win = ObjC.Object(args[0]);
                        console.log("[*] makeKeyAndVisible called on window: " + win.$className);
                    }
                });
            }
        }

        // Check for React Native
        var RCTBridge = ObjC.classes.RCTBridge;
        if (RCTBridge) {
            console.log("[+] React Native detected!");

            // Check if bridge is loaded
            var bridges = ObjC.chooseSync(RCTBridge);
            console.log("[*] RCTBridge instances: " + bridges.length);

            if (bridges.length > 0) {
                var bridge = bridges[0];
                console.log("[+] Bridge instance found: " + bridge);

                // Check if bridge is running
                try {
                    var isLoading = bridge.isLoading();
                    console.log("[*] Bridge isLoading: " + isLoading);
                } catch(e) {
                    console.log("[-] Could not check bridge loading state");
                }
            }
        }

        // Check for SwiftUI
        var UIHostingController = ObjC.classes.UIHostingController;
        if (UIHostingController) {
            console.log("[+] SwiftUI UIHostingController detected!");
        }

        console.log("[*] Diagnosis complete - check output above");
        console.log("[*] Most common white screen causes:");
        console.log("    1. NO RootViewController set on keyWindow");
        console.log("    2. RootViewController view not loaded");
        console.log("    3. View hidden or alpha=0");
        console.log("    4. React Native bridge not initialized");
        console.log("    5. App stuck in background state");

    } catch(e) {
        console.log("[-] Error during diagnosis: " + e);
    }
} else {
    console.log("[-] ObjC runtime NOT available - this might be a pure Swift app");
}
