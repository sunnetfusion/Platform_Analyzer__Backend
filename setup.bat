@echo off
REM Platform Analyzer - Backend Setup Script (Windows)
REM This script sets up the Python virtual environment and installs dependencies

echo 🚀 Setting up Platform Analyzer Backend...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed. Please install Python 3.8 or higher.
    exit /b 1
)

echo ✅ Found Python
python --version

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
    echo ✅ Virtual environment created
) else (
    echo ✅ Virtual environment already exists
)

REM Activate virtual environment
echo 🔌 Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo ⬆️  Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo 📥 Installing dependencies...
REM First upgrade FastAPI, Uvicorn, and Pydantic for Python 3.13 compatibility
pip install --upgrade fastapi uvicorn pydantic
REM Then install all other dependencies
pip install -r requirements.txt

REM Download NLTK data
echo 📚 Downloading NLTK data...
python -c "import nltk; nltk.download('punkt', quiet=True); nltk.download('brown', quiet=True)"

echo.
echo ✅ Setup complete!
echo.
echo To activate the virtual environment, run:
echo   venv\Scripts\activate.bat
echo.
echo To start the backend server, run:
echo   python main.py
echo.

pause

