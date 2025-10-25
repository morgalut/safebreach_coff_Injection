
## sh
```sh
chmod +x compile_enhanced.sh

./compile_enhanced.sh
```


# Inject into notepad (if running)

```sh
# Basic demo with default payload
python run_enhanced_demo_standalone.py

# Target specific process
python run_enhanced_demo_standalone.py --target notepad.exe

# Use different payload type
python run_enhanced_demo_standalone.py --payload-type meterpreter --target explorer.exe

# List available processes
python run_enhanced_demo_standalone.py --list-processes

# Keep generated payload for analysis
python run_enhanced_demo_standalone.py --no-cleanup
```



