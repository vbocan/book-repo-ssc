using System.Text.Encodings.Web;

string inputUtilizator = "<script>alert('XSS')</script>";

// Codificare HTML: pentru afișare în pagină
string htmlSigur = HtmlEncoder.Default.Encode(inputUtilizator);
// Rezultat: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;

// Codificare URL: pentru includere în parametri URL
string urlSigur = UrlEncoder.Default.Encode(inputUtilizator);

// Codificare JavaScript: pentru includere în blocuri <script>
string jsSigur = JavaScriptEncoder.Default.Encode(inputUtilizator);

Console.WriteLine(htmlSigur);
Console.WriteLine(urlSigur);
Console.WriteLine(jsSigur);
