docker build -t securebin .
docker run -p 5000:5000 --name securebin --rm securebin
