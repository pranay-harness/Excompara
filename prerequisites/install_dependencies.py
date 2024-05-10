import subprocess
import sys

def install_dependencies():
    """
    This script will install the required dependencies by reading from the requirements.txt file.
    """
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "prerequisites/requirements.txt"])
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        sys.exit(1)

if __name__ == "__main__":
    install_dependencies()