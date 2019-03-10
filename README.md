### blackmonday
---
https://github.com/microcosm-cc/bluemonday

```go
package main

import (
  "fmt"
  
  "github.com/microcosm-cc/bluemonday"
)

func main() {
  p := bluemonday.UGCPolicy()
  
  html := p.Sanitize(
    `<a onblur="alert(secret)" href="http://www.google.com">Google</a>`,
  )
  
  fmt.Println(html)
}

p.Sanitize(string) string
p.SanitizeBytes([]byte) []byte
p.SanitizeReader(io.Reader) bytes.Buffer

package main

import (
  "fmt"
  
  "github.com/microcosm-cc/bluemonday"
)

func main() {
  p := bluemonday.NewPolicy()
  
  p.AllowStandardURLs()
  
  p.AllowAttrs("href").OnElements("a")
  p.AllowElements("p")
  
  html := p.Sanitize(
    `<a onblur="alert(secret)" href="http://www.google.com">Google</a>`,
  )
  
  fmt.Println(html)
}

p := bluemonday.NewPolicy()

p.AllowElements("b", "strong")

p.AllowAttrs("nowrap").OnElements("td", "th")

p.AllowAttrs("dir").Matching(regexp.MustCompile("(?i)rtl|ltr")).Globally()

p.AllowAttrs("value").OnElements("li")

p.AllowAttrs("title").Matching(regexp.MustCompile(`[\p{L}\p{N}\s\-_'."\[\]!\./\\\(\)&]*`)).Globally()

htmlOut := p.Sanitize(htmlIn)

p := bluemonday.UGCPolicy()
p.AllowElements("fieldset",  "select", "option")

p.AllowAttrs("href").Matching(regexp.MustCompile(`(?i)mailto|https?`)).OnElements("a")

p.RequireParseableURLs(true)

p.AllowRelativeURLs(true)

p.AllowURLSchemes("mailto", "http", "https")

p.RequireNoFollowOnLinks(true)

p.AllowStandardURLs()
p.AllowAttrs("cite").OnElements("blockquote", "q")
p.AllowAttrs("href").OnElements("a", "area")
p.AllowAttrs("src").OnElements("img")

p.AllowDataURIImages()

p.AddTargetBlanktoFullyQualifiedLinks(true)

p.AllowStandardAttributes()
p.AllowImages()
p.AllowLists()
p.AllowTables()

p.AllowAttrs("value")
p.AllowAttrs(
  "type",
).Matchin(
  regexp.MustCompile("(?i)^(circle|disc|square|a|A|i|I|1)"),
)
```

```
Hello <STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>World

<img src="data:image/webp;base64,xxxxxxxxxxxxx//73v/+BiOh/AAA=">

<a href="javacript:alert('XSS1')" onmouseover="alert('XSS2')">XSS</a>

<a href="http://www.google.com/">
  <img src="https://ssl.gstatic.com/accunts/ui/logo_2x.png"/>
</a>

<a href="http://www.google.com/" rel="nofollow">
  <img src="htps://ssl.gstatic.com/accounts/ui/logo_2x.png"/>
</a>
```

```
```


