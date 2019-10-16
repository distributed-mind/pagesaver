### PAGESAVER

Enter a URL and press enter. The resulting links are copies of the page, except that they are hosted on IPFS.
You can also enter youtube URLs.

###
Features:
- save generic html page
- save imgur galleries
- save youtube videos
- save bandcamp albums (soon)

###
This project builds on top of these other projects:
- Monolith: https://github.com/Y2Z/monolith
- youtube-dl: https://github.com/ytdl-org/youtube-dl
- IPFS: https://github.com/ipfs/go-ipfs

###
DEMO:
- run `./build.sh` to start a local instance
- or run `docker-compose up`, and visit http://localhost:8000
- Please check local ipfs node for peers (http://localhost:5001/webui/#/peers), if you do not have any peers, then resulting links will not work because your node needs to be able to transfer the data to another peer. All you need to do is wait about 1 or 2 minutes for your ipfs node to boostrap and find peers, about 100 peers is good enough for the URLs to get "warmed" properly.
- an online demo can be seen here: https://pagesaver.dweb.tools

###
TODO:
- (monoltih) disable javascript for certain sites, (medium.com, reddit, wsj,) 
- cleanup youtube support
- add album viewer html
- rewrite everything
- add bandcamp support
- fix html pages, perhaps ask someone in community
- add file upload feature
- add data.json
- seperate embedded ipfs into own module
