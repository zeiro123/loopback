# Loopback — Test Users & Credentials

> These are synthetic, lab-only credentials for the deliberately vulnerable target and the SOC console. None of them are real accounts. Do not reuse these passwords anywhere.

## Banking customers (Apex Trust Bank — http://localhost:5000)

All 20 customers open with a 500 ZWL deposit plus seeded salary/spend history; balances below are the seeded values at first boot (they change as you transact).

| # | Username | Password | Name | Account | Seeded balance (ZWL) | Occupation |
| --: | :--- | :--- | :--- | :--- | --: | :--- |
| 1 | `Mary` | `peter` | Mary Jane | ACC-1001 | 500 | Retailer |
| 2 | `John` | `peter` | John Doe | ACC-1002 | 500 | Teacher |
| 3 | `Alice` | `peter` | Alice Smith | ACC-1003 | 500 | Engineer |
| 4 | `Bob` | `peter` | Bob Vance | ACC-1004 | 500 | Farmer |
| 5 | `Tendai` | `tendai2026` | Tendai Moyo | ACC-1005 | varies | Accountant |
| 6 | `Rudo` | `rudo2026` | Rudo Chirwa | ACC-1006 | varies | Nurse |
| 7 | `Kudzai` | `kudzai2026` | Kudzai Ncube | ACC-1007 | varies | Software Developer |
| 8 | `Nyasha` | `nyasha2026` | Nyasha Gumbo | ACC-1008 | varies | Logistics |
| 9 | `Chipo` | `chipo2026` | Chipo Marange | ACC-1009 | varies | Lecturer |
| 10 | `Tapiwa` | `tapiwa2026` | Tapiwa Dube | ACC-1010 | varies | Mechanic |
| 11 | `Rutendo` | `rutendo2026` | Rutendo Nyoni | ACC-1011 | varies | Pharmacist |
| 12 | `Farai` | `farai2026` | Farai Katsande | ACC-1012 | varies | Transport |
| 13 | `Munashe` | `munashe2026` | Munashe Zvobgo | ACC-1013 | varies | Student |
| 14 | `Shamiso` | `shamiso2026` | Shamiso Mhaka | ACC-1014 | varies | Journalist |
| 15 | `Takudzwa` | `takudzwa2026` | Takudzwa Siziba | ACC-1015 | varies | Electrician |
| 16 | `Vimbai` | `vimbai2026` | Vimbai Chingono | ACC-1016 | varies | Designer |
| 17 | `Anesu` | `anesu2026` | Anesu Pfumojena | ACC-1017 | varies | Farmer |
| 18 | `Tinotenda` | `tinotenda2026` | Tinotenda Mapfumo | ACC-1018 | varies | Doctor |
| 19 | `Rejoice` | `rejoice2026` | Rejoice Nyemba | ACC-1019 | varies | Broker |
| 20 | `Panashe` | `panashe2026` | Panashe Gurajena | ACC-1020 | varies | Chef |

Every seeded customer also carries 3–6 historical transactions (salary deposits, supermarket/fuel/airtime spend) spread over the last month, and every new registration starts with 500 ZWL.

## SOC operators (Loopback SOC — http://localhost:5100)

| Username | Password | Name | Role |
| :--- | :--- | :--- | :--- |
| `admin` | `admin` | Lead Analyst | admin |
| `nyasha` | `nyasha2026` | Nyasha M. | analyst |
| `chipo` | `chipo2026` | Chipo M. | analyst |
| `farai` | `farai2026` | Farai K. | analyst |
| `rutendo` | `rutendo2026` | Rutendo N. | analyst |
| `tapiwa` | `tapiwa2026` | Tapiwa D. | analyst |

Every operator login (and failed attempt) is recorded in the SOC audit log with IP and user-agent, and every response action is attributed to the operator who took it — log in as different analysts and you'll see attribution change in Response Actions.

## Notes

- Passwords are plain text in the database **by design** — the bank is a vulnerable target.
- Account numbers are sequential and guessable by design (part of the enumeration scenario).
- Reset everything with `docker compose down -v && docker compose up --build -d`.
