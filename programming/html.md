# HTML

A quick reference guide for essential HTML concepts and structures.

---

## 1. Document Structure

Every HTML document starts with a standard structure:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your Title</title>
</head>
<body>
    <!-- Your content goes here -->
</body>
</html>
```

---

## 2. Text Formatting

Structure your text effectively using headings, paragraphs, and emphasis:

```html
<!-- Headings -->
<h1>This is Heading 1</h1>
<h2>This is Heading 2</h2>

<!-- Paragraph -->
<p>This is a paragraph.</p>

<!-- Bold & Italic -->
<strong>Bold Text</strong>
<em>Italic Text</em>

<!-- Line Break -->
<p>First line<br>Second line</p>
```

---

## 3. Links

Create links to other web pages or resources using the `<a>` tag:

```html
<a href="https://example.com" target="_blank" title="Visit Example">Visit Example</a>
```

---

## 4. Images

Use the `<img>` tag to display images with proper descriptions for accessibility:

```html
<img src="image.jpg" alt="Description">
```

**Tip:** Use `width` and `height` attributes to define image dimensions:

```html
<img src="image.jpg" alt="Description" width="300" height="200">
```

---

## 5. Lists

Create ordered and unordered lists to organize content:

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
```

**Tip:** Nest lists to create multi-level structures:

```html
<ul>
    <li>Item 1
        <ul>
            <li>Sub-item 1</li>
            <li>Sub-item 2</li>
        </ul>
    </li>
    <li>Item 2</li>
</ul>
```

---

## 6. Forms

Collect user input using forms:

```html
<form action="/submit" method="post">
    <!-- Text Input -->
    <label for="username">Username:</label>
    <input type="text" id="username" name="username">

    <!-- Password Input -->
    <label for="password">Password:</label>
    <input type="password" id="password" name="password">

    <!-- Submit Button -->
    <input type="submit" value="Submit">
</form>
```

**Tip:** Add `placeholder` to inputs for user guidance:

```html
<input type="text" id="username" name="username" placeholder="Enter your username">
```

---

## 7. Tables

Organize tabular data with the `<table>` element:

```html
<table border="1">
    <tr>
        <th>Header 1</th>
        <th>Header 2</th>
    </tr>
    <tr>
        <td>Data 1</td>
        <td>Data 2</td>
    </tr>
</table>
```

**Tip:** Add captions and style your table for better clarity:

```html
<table border="1">
    <caption>Sample Table</caption>
    <tr>
        <th>Header 1</th>
        <th>Header 2</th>
    </tr>
    <tr>
        <td>Data 1</td>
        <td>Data 2</td>
    </tr>
</table>
```

---

## 8. Divisions & Spans

Use `<div>` for block-level elements and `<span>` for inline styling:

```html
<!-- Division -->
<div>
    <!-- Your content goes here -->
</div>

<!-- Span -->
<p>This is a <span style="color: blue;">blue</span> word.</p>
```

---

## 9. Comments

Add comments to document your code or provide explanations:

```html
<!-- This is a comment -->
```

---

## 10. Scripting

Include JavaScript for dynamic behavior:

```html
<script>
    alert('Hello, World!');
</script>
```

**Tip:** Place scripts at the end of the `<body>` for better performance:

```html
<body>
    <!-- Content -->
    <script>
        console.log('Script loaded after content');
    </script>
</body>
```

---

## 11. Semantic Elements (Bonus Tip)

Use semantic HTML elements for better structure and accessibility:

```html
<header>
    <h1>Page Title</h1>
</header>

<main>
    <section>
        <h2>Section Title</h2>
        <p>Section content goes here.</p>
    </section>
</main>

<footer>
    <p>Footer content goes here.</p>
</footer>
```