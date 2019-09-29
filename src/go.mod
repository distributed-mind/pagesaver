module pagesaver

go 1.13

replace (
	eipfsd => ./eipfsd
	github.com/Sirupsen/logrus => github.com/sirupsen/logrus v1.4.3-0.20190807103436-de736cf91b92
)

require (
	eipfsd v0.0.0-00010101000000-000000000000
	github.com/PuerkitoBio/goquery v1.5.0 // indirect
	github.com/Sirupsen/logrus v1.4.2 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/rylio/ytdl v0.5.1
	github.com/sirupsen/logrus v1.4.2 // indirect
	golang.org/x/net v0.0.0-20190926025831-c00fd9afed17 // indirect
	golang.org/x/sys v0.0.0-20190927073244-c990c680b611 // indirect
)
