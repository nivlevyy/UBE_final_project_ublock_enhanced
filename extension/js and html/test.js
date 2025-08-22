


let examples = [
  "https://site.com/favicon.ico",
  "https://site.com/icon.PNG?123",
  "https://cdn.site.com/image.gif#v2",
  "https://example.com/favicon.svg",
  "https://site.com/iconico"
];

examples.forEach(href => {
  const isValid = /\.(ico|png|gif)([\?#].*)?$/i.test(href);
  console.log(href, "⟶", isValid ? "✅ Valid" : "❌ Invalid");
});
