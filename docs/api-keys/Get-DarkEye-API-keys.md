The `darkeye` engine uses two DarkEye APIs, each with its own optional API key:

- **Have I Been Ransomed?** (HIBR): ransomware victims and data breaches tied to a domain.
- **Breach House**: ransomware victims, data breaches, leads and stealer logs tied to a domain.

Configure one key or both. The engine queries every product that has a key. If one product fails, the records of the other one are still returned, and the failure is shown in the result.

## Have I Been Ransomed?

1. **Visit the API documentation:**  
    - Go to [https://haveibeenransom.com/howapi](https://haveibeenransom.com/howapi).

2. **Get an API plan and sign in:**  
    - Every API plan comes with a personal token. Pick a plan if you do not have one yet, then log in.

3. **Copy your API token:**  
    - The token is available in your profile. Copy the value and store it securely.

4. **Add the key to Cyberbro:**  
    - Export it as an environment variable `DARKEYE_HIBR_API_KEY`, or
    - Set it in the `.env` file using `DARKEYE_HIBR_API_KEY=your_key`.

## Breach House

1. **Visit the API documentation:**  
    - Go to [https://breach.house/docs](https://breach.house/docs).

2. **Sign in to the customer panel:**  
    - Log in to get your API token.

3. **Add the key to Cyberbro:**  
    - Export it as an environment variable `DARKEYE_BREACH_HOUSE_API_KEY`, or
    - Set it in the `.env` file using `DARKEYE_BREACH_HOUSE_API_KEY=your_key`.

!!! note
    Keep your API keys confidential and rotate them immediately if you suspect exposure. Each key has its own quota, managed by DarkEye.

## API Reference

| Product | Endpoint | Documentation |
| :------ | :------- | :------------ |
| Have I Been Ransomed? | `GET https://haveibeenransom.com/api/metadata/domain/{domain}` (paginated, 5 pages at most) | [https://haveibeenransom.com/howapi](https://haveibeenransom.com/howapi) |
| Breach House | `GET https://breach.house/api/v1/search?q={domain}&limit=25` | [https://breach.house/docs](https://breach.house/docs) |

- **Authentication Header:** `Authorization: Bearer <your_key>`
- Only plain domain names are queried (wildcards are rejected). For a URL, the domain is extracted first.
- Only listing metadata is kept for each record: product, category, id, title, website, group, country and discovery date. Leaked content, proof files and download links are never read.
