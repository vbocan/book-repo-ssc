# Aplicația practică 2: codificarea ieșirii și sanitizarea HTML contra XSS (LabXss)

**În carte:** capitolul 9, „Aplicații practice”, Aplicația practică 2.

Compară codificarea HTML a ieșirii (`HtmlEncoder`), un filtru regex **naiv**,
păstrat intenționat doar pentru comparație, și sanitizarea cu `HtmlSanitizer` (pachetul mganss, 9.2.1039).

**Cerințe:** .NET 10 SDK (Anexa A), acces la nuget.org. **Rulare:** `dotnet run`. Ieșirea este deterministă. Cartea tipărește doar testele „Tag neînchis” și „Tag-uri imbricate”; ieșirea completă este mai jos.

## Rezultatul așteptat

```
=== TESTARE SANITIZARE XSS ===

Test: Script simplu
  Input:         <script>alert('XSS')</script>
  Detectat:      script
  Codificat:     &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;
  Regex (naiv):  alert('XSS')
  HtmlSanitizer:

Test: Event handler pe imagine
  Input:         <img src=x onerror=alert('XSS')>
  Detectat:      event handler
  Codificat:     &lt;img src=x onerror=alert(&#x27;XSS&#x27;)&gt;
  Regex (naiv):
  HtmlSanitizer:

Test: JavaScript în href
  Input:         <a href="javascript:alert('XSS')">Click</a>
  Detectat:      javascript:
  Codificat:     &lt;a href=&quot;javascript:alert(&#x27;XSS&#x27;)&quot;&gt;Click&lt;/a&gt;
  Regex (naiv):  Click
  HtmlSanitizer:

Test: SVG cu onload
  Input:         <svg onload=alert('XSS')>
  Detectat:      event handler
  Codificat:     &lt;svg onload=alert(&#x27;XSS&#x27;)&gt;
  Regex (naiv):
  HtmlSanitizer:

Test: Tag neînchis
  Input:         <img src=x onerror=alert(1)
  Detectat:      event handler
  Codificat:     &lt;img src=x onerror=alert(1)
  Regex (naiv):  <img src=x onerror=alert(1)
  HtmlSanitizer:

Test: Tag-uri imbricate
  Input:         <<script>alert('XSS')//<</script>
  Detectat:      script
  Codificat:     &lt;&lt;script&gt;alert(&#x27;XSS&#x27;)//&lt;&lt;/script&gt;
  Regex (naiv):  <alert('XSS')//<
  HtmlSanitizer: &lt;

Test: Tag-uri permise și nepermise
  Input:         <b>Text bold</b><script>alert('XSS')</script><i>italic</i>
  Detectat:      script
  Codificat:     &lt;b&gt;Text bold&lt;/b&gt;&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;&lt;i&gt;italic&lt;/i&gt;
  Regex (naiv):  <b>Text bold</b>alert('XSS')<i>italic</i>
  HtmlSanitizer: <b>Text bold</b><i>italic</i>

Test: Input legitim
  Input:         O <b>recenzie</b> pentru <i>produsul</i> comandat.
  Detectat:      nimic
  Codificat:     O &lt;b&gt;recenzie&lt;/b&gt; pentru &lt;i&gt;produsul&lt;/i&gt; comandat.
  Regex (naiv):  O <b>recenzie</b> pentru <i>produsul</i> comandat.
  HtmlSanitizer: O <b>recenzie</b> pentru <i>produsul</i> comandat.
```
