Java.perform(function() {

    var Modifier = Java.use('java.lang.reflect.Modifier');

    // --- Configuration ---
    var listOnly = true; // TOGGLE: Set to true to just list classes, false to hook them.

    var blacklistedClasses = [
        "java.lang.Class",
        "java.lang.ClassLoader",
        "java.lang.reflect.",
        "java.io.",
        "java.nio.",
        // "java.util.concurrent.",
        // "android.content.",
        // "android.os.",
        // "android.view.",
        // "android.app.",
        // "com.android.internal.",
        // "dalvik.system.",
        // "com.google.android.gms.",
        // "com.google.firebase.",
        // "okhttp3.",
        // "retrofit2.",
        // "rx.internal.",
        // "io.reactivex.internal.",
        // "kotlin.coroutines.",
        // "kotlinx.coroutines.",
        // "a.", "b.", "c."
    ];

    // add them as class.class.method and not with a !
    var whitelistedClassesAndFunctions = []; 

    // Helper function (same as before)
    function stringifyObject(obj) {
        if (obj === null || obj === undefined) {
            return "null";
        }
        try {
            var objClass = obj.getClass();
            var output = "{";
            var visited = new Set();
            
            function processFields(currentObj, cls) {
                if (currentObj == null || visited.has(currentObj)) {
                    return;
                }
                visited.add(currentObj);
                var fields = cls.getDeclaredFields();
                fields.forEach(function(field) {
                    try {
                        field.setAccessible(true);
                        var fieldName = field.getName();
                        var fieldValue = field.get(currentObj);
                        if (output.length > 1) {
                            output += ", ";
                        }
                        output += fieldName + ": " + (fieldValue ? fieldValue.toString() : "null");
                    } catch(e) {}
                });
                var superclass = cls.getSuperclass();
                if (superclass != null) {
                    processFields(currentObj, superclass);
                }
            }
            
            processFields(obj, objClass);
            output += "}";
            return objClass.getName() + "@" + obj.hashCode() + " " + output;
        } catch (e) {
            return obj.toString();
        }
    }
    
    // --- The main logic starts here ---
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            loader.enumerateLoadedClasses({
                onMatch: function(className) {
                    try {
                        var isBlacklisted = blacklistedClasses.some(function(prefix) {
                            return className.startsWith(prefix);
                        });
                        if (isBlacklisted) {
                            return;
                        }
                        
                        var targetClass = loader.use(className);

                        if (whitelistedClassesAndFunctions.length > 0) {
                            var isWhitelisted = whitelistedClassesAndFunctions.some(function(whitelistName) {
                                return className.startsWith(whitelistName) || (className + ".").startsWith(whitelistName);
                            });
                            if (!isWhitelisted) {
                                return;
                            }
                        }

                        // --- Logic for both listing and hooking ---
                        // Get methods and constructors
                        var methods = targetClass.class.getDeclaredMethods();
                        var constructors = targetClass.class.getDeclaredConstructors();

                        if (listOnly) {
                            // --- LISTING MODE ---
                            console.log("[+] Found class: " + className);
                            methods.forEach(function(method) {
                                var methodName = method.getName();
                                console.log("    - Method: " + methodName);
                            });
                            constructors.forEach(function(constructor) {
                                console.log("    - Constructor: " + className);
                            });
                        } else {
                            // --- HOOKING MODE ---
                            
                            // Hook methods
                            methods.forEach(function(method) {
                                var methodName = method.getName();
                                var fullFunctionName = className + "." + methodName;
                                var methodOverloads = targetClass[methodName].overloads;

                                methodOverloads.forEach(function(overload) {
                                    overload.implementation = function() {
                                        var args = Array.prototype.map.call(arguments, stringifyObject);
                                        var isStatic = Modifier.isStatic(method.getModifiers());
                                        var callType = isStatic ? "STATIC" : "INSTANCE";
                                        console.log("[*] CALL (" + callType + "): " + fullFunctionName + "(" + args.join(", ") + ")");
                                        var retval = this[methodName].apply(this, arguments);
                                        console.log("[*] RETURN: " + fullFunctionName + " => " + stringifyObject(retval));
                                        return retval;
                                    };
                                });
                            });
                            
                            // Hook constructors
                            constructors.forEach(function(constructor) {
                                var fullFunctionName = className + ".$init";
                                var constructorOverloads = targetClass['$init'].overloads;
                                
                                constructorOverloads.forEach(function(overload) {
                                    overload.implementation = function() {
                                        var args = Array.prototype.map.call(arguments, stringifyObject);
                                        console.log("[*] CALL (INIT): " + fullFunctionName + "(" + args.join(", ") + ")");
                                        this.$init.apply(this, arguments);
                                        console.log("[*] RETURN: " + fullFunctionName + " => new instance");
                                    };
                                });
                            });
                        }
                    } catch(e) {
                        console.error("Failed to process class " + className + ". Reason: " + e.message);
                    }
                },
                onComplete: function() {
                    // All classes from this loader have been processed
                }
            });
        },
        onComplete: function() {
            console.log("Enumeration of all loaders complete.");
        }
    });
});
