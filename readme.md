


## sh
```sh

cd coff_injection_demo/src
chmod +x compile_enhanced.sh

./compile_enhanced.sh
```


# Inject into notepad (if running)

```sh
# From the directory containing coff_injection_demo folder
python -m coff_injection_demo.main --list-targets
python -m coff_injection_demo.main --target notepad.exe --payload-type demo
```



