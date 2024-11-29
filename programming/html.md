# HTML Cheat Sheet

## 1. Document Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="A brief description of your page">
    <meta name="keywords" content="HTML, CSS, JavaScript">
    <meta name="author" content="Your Name">
    <title>Your Title</title>
    <link rel="stylesheet" href="styles.css"> <!-- Link to CSS file -->
</head>
<body>
    <!-- Your content goes here -->
    <script src="scripts.js"></script> <!-- Link to JavaScript file -->
</body>
</html>
```

## 2. Text Formatting

```html
<!-- Headings -->
<h1>Main Heading</h1>
<h2>Secondary Heading</h2>
<h3>Subheading</h3>

<!-- Paragraph -->
<p>This is a paragraph. It provides textual content.</p>

<!-- Bold & Italic -->
<strong>This text is bold</strong>
<em>This text is italic</em>

<!-- Line Break -->
<p>First line<br>Second line</p>

<!-- Superscript & Subscript -->
<p>Water formula: H<sub>2</sub>O</p>
<p>E=mc<sup>2</sup></p>
```

## 3. Links

```html
<!-- Anchor Tag -->
<a href="https://example.com" target="_blank" title="Visit Example">Visit Example</a>

<!-- Email Link -->
<a href="mailto:email@example.com">Send Email</a>
```

## 4. Images

```html
<!-- Image Tag -->
<img src="image.jpg" alt="Description of the image" width="300" height="200">

<!-- Responsive Image -->
<img src="image.jpg" alt="Description of the image" style="max-width: 100%; height: auto;">
```

## 5. Lists

```html
<!-- Unordered List -->
<ul>
    <li>Item 1</li>
    <li>Item 2</li>
</ul>

<!-- Ordered List -->
<ol>
    <li>Item 1</li>
    <li>Item 2</li>
</ol>

<!-- Nested List -->
<ul>
    <li>Item 1
        <ul>
            <li>Subitem 1</li>
            <li>Subitem 2</li>
        </ul>
    </li>
    <li>Item 2</li>
</ul>
```

## 6. Forms

```html
<form action="/submit" method="post">
    <!-- Text Input -->
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" required>

    <!-- Password Input -->
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required>

    <!-- Radio Buttons -->
    <label>
        <input type="radio" name="gender" value="male"> Male
    </label>
    <label>
        <input type="radio" name="gender" value="female"> Female
    </label>

    <!-- Checkboxes -->
    <label>
        <input type="checkbox" name="subscribe" value="newsletter"> Subscribe to newsletter
    </label>

    <!-- Select Dropdown -->
    <label for="country">Country:</label>
    <select id="country" name="country">
        <option value="us">United States</option>
        <option value="ca">Canada</option>
    </select>

    <!-- Textarea -->
    <label for="comments">Comments:</label>
    <textarea id="comments" name="comments"></textarea>

    <!-- Submit Button -->
    <input type="submit" value="Submit">
</form>
```

## 7. Tables

```html
<!-- Table -->
<table border="1" cellspacing="0" cellpadding="5">
    <thead>
        <tr>
            <th>Header 1</th>
            <th>Header 2</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Data 1</td>
            <td>Data 2</td>
        </tr>
    </tbody>
    <tfoot>
        <tr>
            <td colspan="2">Footer Content</td>
        </tr>
    </tfoot>
</table>
```

## 8. Divisions & Spans

```html
<!-- Division -->
<div class="container">
    <h2>Title</h2>
    <p>Content inside a div.</p>
</div>

<!-- Span -->
<p>This is a <span style="color: blue;">blue</span> word.</p>
```

## 9. Comments

```html
<!-- This is a comment, which is not displayed in the browser -->
```

## 10. Scripting

```html
<!-- Inline Script -->
<script>
    console.log('Hello, World!');
</script>

<!-- External Script -->
<script src="scripts.js"></script>
```

## Additional Resources

- [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTML): Comprehensive resource for HTML.
- [W3Schools](https://www.w3schools.com/html/): Tutorials and references for learning HTML.
