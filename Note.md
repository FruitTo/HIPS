---
title: "Basic Python"
transition: "slide"
---

# NOTE FOR RECODING.

---
## Future

**This variable will get this datatype in future.**

```cpp
// Declare variable.
future<type> name;
future<string> full_name;
```

```cpp
// Callback Function.
string callback(){
    return "Kritsada Ngampaeng";
}

// Use method async(async_type, callback_function).
name = async(launch::async_type, callback);
full_name = async(launch::async, callback);

// Gets already-computed result (or waits if still running) 
name = full_name.get();    

full_name = async(launch::deferred, callback);

// Execute code and return that velue right now.
name = full_name.get();    
```

---

### Async

Async is currently execute on separate thread.

```cpp
future<string> full_name;
// Runing currently.
full_name = async(launch::async, []() {
    return "Kritsada Ngampaeng";
});
```

### Deferred 

Deffed is execute when it called by .get() or .wait()

```cpp
future<string> full_name;
full_name = async(launch::deffered, []() {
    return "Kritsada Ngampaeng";
});
// Runing when call get()
full_name.get();
```

---

## sstream (string stream)

**sstream is a header that contain class to working with string.**
```
─── <sstream> (header)
    ├── std::stringstream     // bidirectional string stream
    ├── std::istringstream    // input string stream  
    ├── std::ostringstream    // output string stream
    └── std::stringbuf        // underlying string buffer
```

```cpp
#include <sstream>
```
