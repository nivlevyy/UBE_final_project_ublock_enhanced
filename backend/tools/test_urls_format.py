
from urllib.parse import urlparse
urls = [
    # "https://www.phish1.evil/shitface",
    # "http://www.phish2.evil/",
    # "http://www.phish3.evil",
    #
    # "https://login.secure-paypal.evil/login",
    # "https://sub.sub2.evil.co/reset/index.html",
    #
    # "phish4.evil",
    # "phish5.evil/",
    # "phish6.evil/login",
    #
    # "https://phish7.evil/a/b/c",
    # "https://phish8.evil/a/b/c/",
    # "https://phish9.evil/login.php",
    # "https://phish10.evil/path/to/index.html",
    #
    # "https://phish11.evil/login?u=1&t=2",
    # "https://phish12.evil/path/?a=1#frag",
    # "http://phish13.evil/?only=query",

    # "http://phish14.evil:8080/",
    # "https://phish15.evil:8443/login",
    #
    # "https://user:pass@phish16.evil/secret",
    # "http://user@phish17.evil/",
    #
    # "http://127.0.0.1/",
    # "https://127.0.0.1/login",
    # "http://192.0.2.123:8080/panel",

    "http://[2001:db8::1]/",
    "https://[2001:db8::2]/admin",
    #
    # "https://bit.ly/fake",
    # "https://t.co/AbCdEfG",
    # "http://tinyurl.com/xyz123",
    #
    # "https://sites.google.com/view/evil-campaign",
    # "https://github.io/health-records-x-ray",
    # "https://subdomain.github.io/repo/page.html",
    # "https://pages.dev/somepath/login",
    # "https://appspot.com/",
    # "https://storage.googleapis.com/bucket/evil/file",
    # "https://s3.amazonaws.com/bucket/key",
    # "https://blogspot.com/evil-post",
    #
    # "https://www.evil1.com",
    # "https://www.evil2.com/",
    # "https://www.evil3.com/login",
    # "http://www.evil4.co.uk/reset",
    #
    # "https://evil5.com",
    # "https://evil6.com/",
    # "https://evil7.com/login",
    #
    # "HTTPS://WWW.EvIl8.CoM/LoGiN",
    # "http://EVIL9.com",
    #
    # "https://evil10.com////multi//slashes",
    # "http://evil11.com/path//to///phish",
    #
    # "https://paypal.com.login.secure.evil.com",
    # "https://microsoft.com.account.verify.evil.net/login",
    #
    # # Punycode (IDN)
    # "https://xn--paypl-6ve.com/login",
    # "http://xn--exmple-cua.com/",
    #
    # "ftp://ftp.evil.com/",
    # "ftp://ftp.evil.com/downloads/steal",
    #
    # "https://rootpath.evil/",
    # "http://rootpath2.evil/",
    #
    # "https://justdomain.evil",
    # "http://justdomain2.evil",
    #
    # "https://shortpath.evil/a",
    # "https://longpath.evil/this/is/a/very/long/path/to/fake/login/index.php",
    #
    # "http://traildot.evil./login",  # שים לב: urlparse.hostname מחזיר בלי הנקודה האחרונה ברוב המקרים
]
def main():

    # urls=["https://www.phish1.evil/shitface", "http://www.phish2.evil/","http://www.phish3.evil"]
    parsed_urls = set()
    text_file=""
    for u in urls:
         parsed = urlparse(u if '://' in u else 'http://' + u)
         if "www." in parsed.hostname:
            host=parsed.hostname.split("www.")[1].lower()
         else:
             host=parsed.hostname
         # print(parsed.path)
         host_for_rule = f'[{host}]' if ':' in host else host

         path = parsed.path or ''
         if path and path != '/':
             rule = f'||{host_for_rule}{path}$document,frame'
         else:
             rule = f'||{host_for_rule}^$all'
         parsed_urls.add(rule)
         text_file = "\n".join(sorted(parsed_urls))+"\n"
         print(rule)
    print('---------------boyaaaa----------')
    print(f'\n{text_file}')
    print("\n---------original-----------------------sorted")
    print(f'\n{sorted(urls)}')






    # new1=[row.replace("https://","") if "https://" in row else row.replace("http://","") for row in urls ]
    # print(new1)
    # # new2=[row.replace("https://","")  for row in urls ]
    # # print(new2)
    #
    #
    #
    # all_urls = ["||" + row + "^$all" for row in new1]
    # all_urls.sort()
    # text_file = "\n".join(all_urls)
    # print(text_file)



if __name__ == "__main__":
    main()