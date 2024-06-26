## Store output katana to elasticsearch

***go build***
```
go build -o katana-report main.go
```
***Edit config***
Edit file `config.yaml`
```
host: "IP/HOST"
port: 9200
ssl: false
ssl-verification: false
username: ""
password: ""
index-name: "katana"
```
***Usage***
```
cat urls.txt | katana -silent -js-crawl -jsluice -jsonl | katana-report
```
![katana](katana.png)
