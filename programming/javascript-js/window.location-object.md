# window.location object

In JavaScript, the `window.location` object has several properties that you can use to get information about the current URL or manipulate it. Here are some key properties and methods:

1.  **window.location.hash**: Returns the anchor part of a URL, including the hash sign (`#`).

    ```javascript
    console.log(window.location.hash); // e.g., "#section1"
    ```
2.  **window.location.href**: Returns the entire URL of the current page.

    ```javascript
    console.log(window.location.href); // e.g., "https://www.example.com/page?query=123#section1"
    ```
3.  **window.location.protocol**: Returns the protocol scheme of the URL, including the final colon (`:`).

    ```javascript
    console.log(window.location.protocol); // e.g., "https:"
    ```
4.  **window.location.host**: Returns the host (hostname and port) of the URL.

    ```javascript
    console.log(window.location.host); // e.g., "www.example.com:80"
    ```
5.  **window.location.hostname**: Returns the domain name of the web host.

    ```javascript
    console.log(window.location.hostname); // e.g., "www.example.com"
    ```
6.  **window.location.port**: Returns the port number of the URL.

    ```javascript
    console.log(window.location.port); // e.g., "80"
    ```
7.  **window.location.pathname**: Returns the path of the URL.

    ```javascript
    console.log(window.location.pathname); // e.g., "/page"
    ```
8.  **window.location.search**: Returns the query string of the URL, including the question mark (`?`).

    ```javascript
    console.log(window.location.search); // e.g., "?query=123"
    ```

#### Methods

1.  **window.location.assign(url)**: Loads the resource at the URL provided.

    ```javascript
    window.location.assign('https://www.example.com');
    ```
2.  **window.location.replace(url)**: Replaces the current document with the one at the URL provided. This method does not create a new entry in the browser's history.

    ```javascript
    window.location.replace('https://www.example.com');
    ```
3.  **window.location.reload(forceReload)**: Reloads the current URL. If `forceReload` is true, the page will be reloaded from the server.

    ```javascript
    window.location.reload(); // Reloads the page from the cache
    window.location.reload(true); // Reloads the page from the server
    ```

These properties and methods are useful for manipulating the URL or redirecting the user to a different page.
