# DabbaDash – Food Delivery Order Platform (Group 3)

**Training application, ITM Secure Application Development course.**
You'll work on this app for the whole subject. Treat it as your company's real product.

## About DabbaDash
DabbaDash is a food delivery start-up from Indore, now live in Indore and Bhopal with about 1,200 partner restaurants, 2,500 riders and 3 lakh customers.
The business is **API-first**: the customer app, the restaurant app and the rider app are all mobile apps that talk to one JSON API (`/api/v1/...`).
Customers order food, restaurants accept and prepare orders, riders pick them up and deliver them, and the operations admin watches everything.
The web pages in this repo are a small console used for demos and by the operations team.

The platform stores customer names, phone numbers and home addresses, which are personal data under the DPDP Act 2023. Riders see customer addresses, so access control matters a lot here.

## Run it (5 minutes)
**Mac / Linux (AWS lab):**
```bash
cd G3_DabbaDash_Orders
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

**Windows (PowerShell):**
```powershell
cd G3_DabbaDash_Orders
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:5050** in your browser.
To reset all data, stop the app (Ctrl+C), delete `orders.db` and start it again.
If port 5050 is busy, choose another: `PORT=5051 python3 app.py` (Mac/Linux) or `$env:PORT=5051; python app.py` (Windows).

> Always use `python -m pip …` rather than plain `pip` – it also works on machines where security policies block `pip.exe`.
> The app only listens on your own machine. Never host it on a public server.

## Test accounts
| Role | Username | Password |
|---|---|---|
| Customer | priya | Priya@123 |
| Customer | kabir | Kabir@123 |
| Restaurant (Sarafa Swad) | sarafa | Rest@123 |
| Rider | rider.ravi | Rider@123 |

You can also register new customer accounts, on the web page or through the API.

## Order life cycle
Placed → Preparing → Ready (restaurant) → Picked up → Delivered (rider)

## Using the API (this is how the mobile apps work)
1. Log in and copy the `token` from the reply.
2. Send it in every call as the header `Authorization: Bearer <token>`.

**Mac / Linux:**
```bash
curl -s -X POST http://127.0.0.1:5050/api/v1/login -H "Content-Type: application/json" \
     -d '{"username":"kabir","password":"Kabir@123"}'

curl -s http://127.0.0.1:5050/api/v1/orders -H "Authorization: Bearer <token>"

curl -s -X POST http://127.0.0.1:5050/api/v1/orders -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"restaurant_id":2,"items":[{"menu_id":4,"qty":2}],"delivery_note":"Call on arrival"}'
```

**Windows (PowerShell):**
```powershell
$r = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5050/api/v1/login -ContentType "application/json" `
     -Body '{"username":"kabir","password":"Kabir@123"}'
$h = @{ Authorization = "Bearer " + $r.token }
Invoke-RestMethod -Uri http://127.0.0.1:5050/api/v1/orders -Headers $h
```
Postman, Insomnia or Burp Repeater work just as well.

## Map of the app
**API**
| Call | What it does |
|---|---|
| `POST /api/v1/register` | Customer sign-up: `{"username","password","full_name","phone","address"}` |
| `POST /api/v1/login` | Returns a token: `{"username": "...", "password": "..."}` |
| `GET /api/v1/restaurants` | List of restaurants (no login needed) |
| `GET /api/v1/restaurants/<id>/menu` | Menu of one restaurant (no login needed) |
| `GET /api/v1/orders` | My orders |
| `POST /api/v1/orders` | Place an order: `{"restaurant_id", "items":[{"menu_id","qty"}], "delivery_note"}` |
| `GET /api/v1/orders/<id>` | One order, with customer contact details for the rider |
| `PATCH /api/v1/orders/<id>` | Update an order (for example, change the delivery note) |
| `GET /api/v1/users/<id>` | One user profile |
| `GET /api/v1/admin/users` | All users (for the operations team) |

**Web console**
| URL | What it does |
|---|---|
| `/login`, `/register`, `/logout` | Sign in, customer sign-up, sign out |
| `/customer` | Order food, my orders, my API token |
| `/restaurant` | Incoming orders, mark Preparing / Ready |
| `/rider` | Pickups and deliveries, mark Picked up / Delivered |
| `/admin` | All orders and users (admin only) |

## Files
- `app.py`: all application logic (about 410 lines)
- `templates/`: HTML pages (Jinja2)
- `orders.db`: SQLite database, created on first run

## Ground rules
1. Test only your own copy running on `127.0.0.1`.
2. Keep every change in Git so you can show "before vs after".
3. You may use AI tools, but every team member must be able to explain any line you changed.
