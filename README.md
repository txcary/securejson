# securejson
A solution to secure the json content between BE and FE. The secure content only handled by FE, BE verify user's signature and store the encrypted secure content, but never know what is it. 

FE implemented by js, BE implemented by go.

## How to use (for browser)

### In HTML
In your html file, require.js is needed to be included.
Below is an example to include the require.js from a CDN, and indicate the main file of javascript is "js/main.js".
```html
<script data-main="js/main.js" src="https://cdn.bootcss.com/require.js/2.3.5/require.js"></script>
```

### In js
In your main file of javascript, the path of dependency libs should be defined in order to let require.js find the dependency.
Then, a object of securejson should be created, using require() function provided by require.js.
Then, call the function "GenerateJson" to generate a secured json string.
Below is an example of main.js
```javascript
var secureJson;

require.config({
	baseUrl: 'js',
	paths: {
		securejson: '3rd/securejson',
		elliptic: "3rd/elliptic/elliptic.min",
		sha3: "3rd/sha3/sha3.min",
		aes: "3rd/aes/index.min",
		base64: "3rd/base64/base64js.min"
	},
});
require(['securejson'], function(sj){
	secureJson = sj;
});
var jsonString = secureJson.GenerateJson("My User Name", "My Password", "My sucure data");
console.log(jsonString);
```

And, for this example, the file structure shoud be like this:
```
js/
js/3rd/
js/3rd/aes/
js/3rd/aes/index.min.js
js/3rd/base64/
js/3rd/base64/base64js.min.js
js/3rd/elliptic/
js/3rd/elliptic/elliptic.min.js
js/3rd/sha3/
js/3rd/sha3/sha3.min.js
js/securejson.js
js/main.js
```

## API
```
GenerateJson(userName, passwd, data)
```
- userName: The user name to identify the owner of the data.
- passwd: User password. It's used to generate the private key used for signing the json, and also used to encrypt the plain data.
- data: The plain data to be secured.

