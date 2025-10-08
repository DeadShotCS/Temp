// A helper function to recursively inspect an object and its fields
function inspectAndPrint(object, depth = 0, maxDepth = 3) {
  if (depth > maxDepth) {
    return `${'  '.repeat(depth)}[Object truncated at max depth]`;
  }
  
  if (object === null) {
    return 'null';
  }
  
  try {
    const objectClass = object.getClass();
    const className = objectClass.getName();
    
    // Check for common types that don't need deep inspection
    if (className.startsWith('java.lang.') || className.startsWith('boolean') || className.startsWith('char') || className.startsWith('short') || className.startsWith('int') || className.startsWith('long') || className.startsWith('float') || className.startsWith('double') || className.startsWith('void')) {
      if (className.includes('String')) {
        return `"${object.toString()}"`;
      }
      return object.toString();
    }
    
    // --- FIX: Handle Arrays ---
    if (className.startsWith('[L')) {
      let arrayInfo = `${'  '.repeat(depth)}[Array: ${className}]\n`;
      try {
        const length = Java.cast(object, Java.array(Java.classFactory.use(className.substring(2, className.length - 1)))).length;
        arrayInfo += `${'  '.repeat(depth + 1)}Length: ${length}\n`;
        for (let i = 0; i < Math.min(length, 5); i++) { // Limit array inspection to 5 elements
            arrayInfo += `${'  '.repeat(depth + 1)}Element ${i}:\n`;
            arrayInfo += inspectAndPrint(object[i], depth + 2, maxDepth);
        }
        if (length > 5) {
             arrayInfo += `${'  '.repeat(depth + 1)}... ${length - 5} more elements\n`;
        }
      } catch (e) {
        arrayInfo += `${'  '.repeat(depth + 1)}<Error inspecting array: ${e}>\n`;
      }
      return arrayInfo;
    }
    
    // --- Rest of the function (object inspection) ---
    let result = `${'  '.repeat(depth)}[Object: ${className}]\n`;
    
    const fields = objectClass.getDeclaredFields();
    
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      field.setAccessible(true);
      const fieldName = field.getName();
      const fieldType = field.getType().getName();
      
      let fieldValue;
      try {
        fieldValue = field.get(object);
      } catch (e) {
        fieldValue = `[Error getting value: ${e}]`;
      }
      
      result += `${'  '.repeat(depth + 1)}Field: ${fieldName} (${fieldType})\n`;
      if (fieldValue !== null) {
        result += inspectAndPrint(fieldValue, depth + 2, maxDepth);
      } else {
        result += `${'  '.repeat(depth + 2)}<null>\n`;
      }
    }
    
    return result;
    
  } catch (e) {
    return `${'  '.repeat(depth)}[Error inspecting object: ${e}]`;
  }
}

// --- FIX: Added try...catch for graceful error handling ---
try {
  Java.perform(function() {
    const targetClassName = 'com.example.MyClass'; 
    const targetMethodName = 'myMethod'; 
    
    const MyClass = Java.use(targetClassName);
    
    MyClass[targetMethodName].overload().implementation = function(...args) {
      console.log(`\n======================================================`);
      console.log(`Intercepting ${targetClassName}.${targetMethodName}`);
      
      console.log(`\nArguments:`);
      if (args.length > 0) {
        for (let i = 0; i < args.length; i++) {
          console.log(inspectAndPrint(args[i]));
        }
      } else {
        console.log(`  <none>`);
      }
      
      const returnValue = this[targetMethodName](...args);
      
      console.log(`\nReturn Value:`);
      console.log(inspectAndPrint(returnValue));
      console.log(`======================================================\n`);
      
      return returnValue;
    };
  });
} catch (e) {
  console.error("Error loading Frida script:", e.message);
}
