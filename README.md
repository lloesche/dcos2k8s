# dcos2k8s
Simple DC/OS app to K8S Deployment/Secrets/ConfigMaps converter
This tool is just to get you started. The resulting files WILL require manual editing!

The tools `dcos` and `kubectl` must be installed on your system and available in your `$PATH`
or specified via `--dcos` and `--kubectl`.

The script takes an arg `--app` followed by the name of the DC/OS app that should be converted to a K8S deployment.

For debugging `--verbose` can be specified.

## Example Usage
```
# Install
git clone https://github.com/lloesche/dcos2k8s.git
cd dcos2k8s
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Usage
dcos auth login
./dcos2k8s.py --app cloudkeeper/aws > app.yaml
```
