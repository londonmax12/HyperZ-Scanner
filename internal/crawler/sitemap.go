package crawler

import (
	"encoding/xml"
	"io"
)

// sitemapDoc matches both <urlset> (regular sitemap with <url><loc>) and
// <sitemapindex> (with <sitemap><loc>) — encoding/xml ignores the root name
// and picks children by their element name, so one struct handles both.
type sitemapDoc struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// parseSitemap returns concrete page URLs and any nested sitemap URLs found.
// Gzipped sitemaps (.xml.gz) are not handled — caller must decompress.
func parseSitemap(r io.Reader) (urls []string, nested []string, err error) {
	var doc sitemapDoc
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, nil, err
	}
	for _, u := range doc.URLs {
		if u.Loc != "" {
			urls = append(urls, u.Loc)
		}
	}
	for _, s := range doc.Sitemaps {
		if s.Loc != "" {
			nested = append(nested, s.Loc)
		}
	}
	return urls, nested, nil
}
