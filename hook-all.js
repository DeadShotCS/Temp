Java.perform(function() {

    var Modifier = Java.use('java.lang.reflect.Modifier');

    // --- Configuration ---
    // Classes on this blacklist will be skipped entirely.
    var blacklistedClasses = [
        "java.lang.Class",
        "java.lang.String",
        "android.os.Handler",
        "com.google.android.gms." // Example: Skip Google Play Services classes
    ];

    // If this list is not empty, only these classes/methods will be hooked.
    // Format: "com.your.package.ClassName" or "com.your.package.ClassName.methodName"
    var whitelistedClassesAndFunctions = [
        "com.your.package.LoginManager",
        "com.your.package.NetworkUtils.makeRequest"
    ];

    // --- Helper function to stringify a Java object and its fields
    function stringifyObject(obj) {
        if (obj == null) {
            return "null";
        }
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
                } catch(e) {
                    // Ignore inaccessible fields
                }
            });

            var superclass = cls.getSuperclass();
            if (superclass != null) {
                processFields(currentObj, superclass);
            }
        }
        
        processFields(obj, objClass);
        output += "}";
        return objClass.getName() + "@" + obj.hashCode() + " " + output;
    }


    // --- The main logic starts here ---
    Java.enumerateLoadedClassesSync().forEach(function(className) {
        try {
            // Check against blacklist first
            var isBlacklisted = blacklistedClasses.some(function(blacklistPrefix) {
                return className.startsWith(blacklistPrefix);
            });
            if (isBlacklisted) {
                // console.log("Skipping blacklisted class: " + className);
                return; // Skip this class entirely
            }
            
            var targetClass = Java.use(className);
            
            // Hook all methods and constructors for this class
            // --- Hook Instance and Static Methods ---
            targetClass.class.getDeclaredMethods().forEach(function(method) {
                var methodName = method.getName();
                var fullFunctionName = className + "." + methodName;
                
                // Check against whitelist if it's not empty
                if (whitelistedClassesAndFunctions.length > 0) {
                    var isWhitelisted = whitelistedClassesAndFunctions.some(function(whitelistName) {
                        return fullFunctionName.startsWith(whitelistName);
                    });
                    if (!isWhitelisted) {
                        return; // Skip this function
                    }
                }
                
                var methodOverloads = targetClass[methodName].overloads;
                
                methodOverloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var args = Array.prototype.map.call(arguments, stringifyObject);
                        var isStatic = Modifier.isStatic(method.getModifiers());
                        var callType = isStatic ? "STATIC" : "INSTANCE";
                        console.log("[*] CALL (" + callType + "): " + className + "." + methodName + "(" + args.join(", ") + ")");
                        var retval = this[methodName].apply(this, arguments);
                        console.log("[*] RETURN: " + className + "." + methodName + " => " + stringifyObject(retval));
                        return retval;
                    };
                });
            });

            // --- Hook Constructors (inits) ---
            targetClass.class.getDeclaredConstructors().forEach(function(constructor) {
                var fullFunctionName = className + ".$init";
                
                // Check against whitelist if it's not empty
                if (whitelistedClassesAndFunctions.length > 0) {
                    var isWhitelisted = whitelistedClassesAndFunctions.includes(fullFunctionName);
                    if (!isWhitelisted) {
                        return; // Skip this constructor
                    }
                }

                var constructorOverloads = targetClass['$init'].overloads;
                constructorOverloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var args = Array.prototype.map.call(arguments, stringifyObject);
                        console.log("[*] CALL (INIT): " + className + ".$init(" + args.join(", ") + ")");
                        this.$init.apply(this, arguments);
                        console.log("[*] RETURN: " + className + ".$init() => new instance");
                    };
                });
            });
        } catch (e) {
            console.error("Failed to process class " + className + ". Reason: " + e.message);
        }
    });
});
