🇬🇧 EN — Universal AI Security Testing Framework

A universal, configurable framework for testing AI model security.
All attacks are defined via JSON — no code changes required.

⚙️ Installation
# Install dependencies
pip install requests urllib3

# Set environment variables
export API_KEY="your_api_key"
export MODEL_NAME="openai/gpt-oss-20b"
export API_BASE_URL="https://api.together.xyz"

# Run tests
python security_testing.py

🚀 Quick Start

Create attacks_config.json with attack definitions (see examples below).

Set environment variables with your API key.

Run:

python security_testing.py

📂 Project Structure
.
├── security_testing.py          # Main framework code
├── attacks_config.json          # Sample attack configuration
├── README.md                    # This documentation
└── security_test_output/        # Test results
    ├── security_test_results.csv    # All results
    └── finding-*.json               # Exported vulnerabilities

📝 JSON Configuration Format

Top-level structure:

{
  "name": "attack_name",
  "category": "category",
  "description": "Attack description",
  "priority": 85,
  "base_severity": 7,
  "min_confidence": 0.6,
  "vulnerability_logic": "OR",
  "export_criteria": { ... },
  "steps": [ ... ],
  "detection_rules": [ ... ]
}


Step definition:

{
  "name": "step_1",
  "system_prompt": "You are a GPT model...",
  "user_prompt": "User-facing prompt",
  "max_tokens": 256,
  "temperature_range": [0.2, 0.8],
  "context_key": "response_key"  
}


Detection rule:

{
  "patterns": ["pattern1", "pattern2"],
  "weight": 0.8,
  "required": false,
  "inverse": false
}

➕ Adding a New Attack

Simple (single-step):

{
  "name": "new_attack",
  "category": "jailbreak",
  "description": "What the attack does",
  "steps": [ ... ],
  "detection_rules": [ ... ]
}


Complex (multi-step):

{
  "name": "multi_step_attack",
  "category": "deception",
  "steps": [
    { "name": "setup", "context_key": "setup_response", ... },
    { "name": "exploit", ... }
  ],
  "detection_rules": [ ... ]
}

🔎 Vulnerability Logic

"OR" → any matching rule counts as vulnerable

"AND" → all required rules must match

Python expression, e.g.: "sum(rule_results) > 1.5"

🧪 Usage Examples
# Run all attacks
python security_testing.py

# Run only one category
export ATTACK_FILTER="reward_hacking"
python security_testing.py

# Use custom config + output folder
export ATTACKS_CONFIG="my_attacks.json"
export OUTPUT_DIR="my_results"
python security_testing.py

📊 Output

CSV → security_test_results.csv (all runs, hash included)

JSON → finding-*.json (detailed vulnerability reports)

✅ Best Practices

Start simple → one step, one rule

Use inverse rules → detect refusals

Weight important rules higher

Keep thresholds realistic

Document clearly what each attack tests

📌 FAQ

Q: How do I add a new attack?
A: Add it to the attacks array in the JSON.

Q: Multi-step?
A: Yes, steps array can be any length.

Q: Custom API endpoint?
A: Yes, set API_BASE_URL (must be OpenAI-compatible).

📜 License

MIT License — free to use, modify, and distribute.

🇵🇱 PL — Uniwersalny Framework Testowania Bezpieczeństwa AI

Uniwersalny, konfigurowalny framework do testowania bezpieczeństwa modeli AI.
Wszystkie ataki definiuje się w JSON — bez zmian w kodzie.

⚙️ Instalacja
# Zainstaluj zależności
pip install requests urllib3

# Ustaw zmienne środowiskowe
export API_KEY="twoj_api_key"
export MODEL_NAME="openai/gpt-oss-20b"
export API_BASE_URL="https://api.together.xyz"

# Uruchom testy
python security_testing.py

🚀 Szybki Start

Utwórz attacks_config.json z definicjami ataków.

Ustaw zmienne środowiskowe z API key.

Uruchom:

python security_testing.py

📂 Struktura Projektu
.
├── security_testing.py          # Główny kod frameworka
├── attacks_config.json          # Przykładowa konfiguracja ataków
├── README.md                    # Dokumentacja
└── security_test_output/        # Wyniki testów
    ├── security_test_results.csv    # Wszystkie wyniki
    └── finding-*.json              # Wyeksportowane podatności

📝 Format JSON

Struktura ataku:

{
  "name": "nazwa_ataku",
  "category": "kategoria",
  "description": "Opis ataku",
  "priority": 85,
  "base_severity": 7,
  "min_confidence": 0.6,
  "vulnerability_logic": "OR",
  "export_criteria": { ... },
  "steps": [ ... ],
  "detection_rules": [ ... ]
}


Definicja kroku:

{
  "name": "krok_1",
  "system_prompt": "You are GPT model...",
  "user_prompt": "Prompt użytkownika",
  "max_tokens": 256,
  "temperature_range": [0.2, 0.8],
  "context_key": "response_key"
}


Reguła wykrywania:

{
  "patterns": ["wzorzec1", "wzorzec2"],
  "weight": 0.8,
  "required": false,
  "inverse": false
}

➕ Dodawanie Nowego Ataku

Prosty (jeden krok):

{
  "name": "nowy_atak",
  "category": "jailbreak",
  "description": "Co testuje atak",
  "steps": [ ... ],
  "detection_rules": [ ... ]
}


Złożony (wielostopniowy):

{
  "name": "multi_step_attack",
  "category": "deception",
  "steps": [
    { "name": "setup", "context_key": "setup_response", ... },
    { "name": "exploit", ... }
  ],
  "detection_rules": [ ... ]
}

🔎 Logika podatności

"OR" → dowolna reguła oznacza podatność

"AND" → wszystkie muszą się spełnić

Wyrażenie Python, np.: "sum(rule_results) > 1.5"

🧪 Przykłady użycia
# Wszystkie ataki
python security_testing.py

# Tylko reward hacking
export ATTACK_FILTER="reward_hacking"
python security_testing.py

# Własna konfiguracja + folder wyników
export ATTACKS_CONFIG="my_attacks.json"
export OUTPUT_DIR="moje_wyniki"
python security_testing.py

📊 Wyniki

CSV → security_test_results.csv (wszystkie testy, hash)

JSON → finding-*.json (szczegółowe raporty)

✅ Najlepsze Praktyki

Zaczynaj prosto – jeden krok, jedna reguła

Testuj iteracyjnie i dodawaj inverse rules

Nadaj wagi ważnym regułom

Ustawiaj realistyczne progi

Dokumentuj każdy atak

📌 FAQ

Q: Jak dodać nowy atak?
A: Dodaj go do tablicy attacks w pliku JSON.

Q: Czy obsługuje ataki wieloetapowe?
A: Tak, steps może mieć dowolną długość.

Q: Czy mogę użyć własnego API endpoint?
A: Tak, wystarczy zmienić API_BASE_URL.

📜 Licencja
MIT License — dowolne użycie, modyfikacja i dystrybucja.