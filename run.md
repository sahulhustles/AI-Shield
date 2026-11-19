# 1. Clone the repository and navigate into it
git clone https://github.com/sahulhustles/AI-Shield.git
cd AI-Shield

# 2. Switch to the zeroth branch
git checkout zeroth

# 3. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Note: If PowerShell gives an execution policy error, run:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 4. Install all dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 5. Create your local environment file
copy .env.example .env

# 6. Run the application
python app.py