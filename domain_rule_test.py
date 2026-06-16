import concurrent.futures
import pandas as pd
import requests

# A curated list of 20 major national news websites from developed countries
NEWS_SITES = {
    # United States
    "The New York Times": "https://www.nytimes.com",
    "The Washington Post": "https://www.washingtonpost.com",
    "CNN": "https://www.cnn.com",
    "WSJ": "https://www.wsj.com",
    # United Kingdom
    "BBC News": "https://www.bbc.co.uk",
    "The Guardian": "https://www.theguardian.com",
    "Reuters": "https://www.reuters.com",
    "The Times UK": "https://www.thetimes.com",
    # Canada
    "CBC News": "https://www.cbc.ca",
    "The Globe and Mail": "https://www.theglobeandmail.com",
    "Global News Canada": "https://globalnews.ca",
    # Australia
    "ABC News AU": "https://www.abc.net.au",
    "The Sydney Morning Herald": "https://www.smh.com.au",
    "The Age": "https://www.theage.com.au",
    # Germany / Europe
    "Deutsche Welle": "https://www.dw.com",
    "Der Spiegel": "https://www.spiegel.de",
    "France 24": "https://www.france24.com",
    # Japan / International
    "The Japan Times": "https://www.japantimes.co.jp",
    "Bloomberg": "https://www.bloomberg.com",
    "Financial Times": "https://www.ft.com",
}


def check_status(name, url):
    """Checks the HTTP status of a given URL."""
    # Using a standard browser User-Agent to prevent sites from blocking the script as a bot
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        # Sending a GET request with a 10-second timeout
        response = requests.get(url, headers=headers, timeout=10)
        return {
            "Website": name,
            "URL": url,
            "HTTP Status": response.status_code,
            "Reason": response.reason,
            "Status": "✅ Available" if response.status_code == 200 else "⚠️ Issue",
        }
    except requests.exceptions.RequestException as e:
        return {
            "Website": name,
            "URL": url,
            "HTTP Status": "ERROR",
            "Reason": str(type(e).__name__),
            "Status": "❌ Down / Unreachable",
        }


def main():
    print(f"Checking {len(NEWS_SITES)} major national news websites...\n")

    results = []

    # Using ThreadPoolExecutor to check websites concurrently (much faster than a sequential loop)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all tasks to the executor
        future_to_url = {
            executor.submit(check_status, name, url): name
            for name, url in NEWS_SITES.items()
        }

        # Gather results as they complete
        for future in concurrent.futures.as_completed(future_to_url):
            results.append(future.result())

    # Convert results to a Pandas DataFrame for clean tabular formatting
    df = pd.DataFrame(results)

    # Sort alphabetically by website name
    df = df.sort_values(by="Website").reset_index(drop=True)

    # Display the final report
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
