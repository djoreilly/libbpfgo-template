# libbpfgo gonew template

Quickly start a new [libbpfgo](https://github.com/aquasecurity/libbpfgo) project with this [gonew](https://pkg.go.dev/golang.org/x/tools/cmd/gonew) template.
```bash
$ go install golang.org/x/tools/cmd/gonew@latest
$ gonew github.com/djoreilly/libbpfgo-template your.domain/myprog
```

Submodules don't seem to work with gonew, so add it manually:
```bash
$ cd myprog
$ git init
$ git submodule add https://github.com/libbpf/libbpf.git
```
