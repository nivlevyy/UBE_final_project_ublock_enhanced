from selenium.webdriver.support.ui import WebDriverWait
from typing import Tuple
from features_extraction.config_models import  config_parmas as cp
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from tldextract import extract
import re
import pandas as pd
import os
import logging
from multiprocessing import Process
import requests

def get_project_root():
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__))
    )
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    datefmt='%H:%M:%S')



SUSPICIOUS_WORDS_REGEX = re.compile(
    r"(log[\s\-]?in|sign[\s\-]?in|auth|user(name)?|email|phone|account|"
    r"credential|password|passcode|pin|security[\s\-]?code|credit[\s\-]?card|cvv|expiry|iban|bank)",
    re.IGNORECASE)


def element_extraction_from_html(soup_html: BeautifulSoup, tag: str = None, attribute=None) -> list:
    if soup_html is None:
        logging.warning(f"[WARN] soup_html is None for tag={tag}, attribute={attribute}")
        return []
    try:
        if not tag:
            return []
        if attribute:
            return soup_html.find_all(tag, **{attribute: True})
        else:
            return soup_html.find_all(tag)
    except Exception as e:
        logging.error(f"[ERROR] Failed to extract elements for tag={tag} attribute={attribute}: {e}")
        return []

def normalize_domain(url: str):
    try:
        parts_of_url = extract(url)
        if not (parts_of_url.domain and parts_of_url.suffix):
            return None
        domain = f"{parts_of_url.domain}.{parts_of_url.suffix}"
        return domain
    except Exception as e:
        logging.error(f"[ERROR] Failed to normalize domain for url={url}: {e}")
        return None

''' specific  function: check the html element that competable with each tag that indicates for a phishing site '''

def safe_extract(tag, attribute):
    try:
        if tag and hasattr(tag, 'get'):
            return tag.get(attribute, "").strip()
        else:
            return ""
    except Exception as e:
        logging.error(f"[ERROR] safe_extract failed for attribute={attribute}: {e}")
        return ""


#####################1-favicon#############################

def has_icon_func(icon_links:list)->int:
    return 1 if len(icon_links) > 0 else 0


# <link> tag ,attr - href=
def favicon_check(link_tag: list, base_domain: str) -> Tuple[int, int, int]:
    icon_links = []
    expected_domain = base_domain.lower()
    favicon_domain_not_the_same = 0
    favicon_invalid_ext = 0
    seen_hrefs = set()

    for link in link_tag:
        try:
            rel = link.get("rel", [])
            if any("icon" in r.lower() for r in rel):
                href = safe_extract(link, "href")
                if href and href not in seen_hrefs:
                    icon_links.append(href)
                    seen_hrefs.add(href)
        except Exception as e:
            logging.warning(f"[WARN] favicon_check rel extract failed: {e}")
            continue
    if not icon_links:
        return 0, 0, 0
    has_icon = has_icon_func(icon_links)

    for href in icon_links:
        try:
            href_domain = normalize_domain(href)
            if not href_domain:
                continue
        except Exception:
            continue

        domain = href_domain.lower()
        try:
            if any(domain.endswith(safe) for safe in cp.get_known_favicon_hosts()):
                continue

            if domain != expected_domain:
                favicon_domain_not_the_same += 1

            if not re.search(r"\.(ico|png|gif)([\?#].*)?$", href, re.IGNORECASE):
                favicon_invalid_ext += 1
        except Exception:
            continue

    return has_icon, favicon_domain_not_the_same, favicon_invalid_ext


#####################2-anchor#############################
# <a> tag ,attr - href=

def extract_url_of_anchor_feature(a_list: list, base_domain) -> Tuple[int, int, int,int]:
    anchor_tags_count = len(a_list)
    anchor_empty_href_count = 0
    anchor_diff_count = 0

    for tag in a_list:
        try:
            href = safe_extract(tag, "href")

            if (not href) or href.strip() in ["#", "javascript:void(0);", "javascript:"]:
                anchor_empty_href_count += 1
                continue

            href_domain = normalize_domain(href)
            if not href_domain:
                continue

            if href_domain != base_domain:
                anchor_diff_count += 1

        except Exception as e:
            logging.error(f"[ERROR] Failed processing anchor tag: {e}")
            continue

    try:
        valid_anchors = anchor_tags_count-anchor_empty_href_count
        anchor_diff_ratio = anchor_diff_count / valid_anchors if valid_anchors > 0 else 0.0
    except Exception as e:
        logging.warning(f"[WARN] Failed to compute anchor_diff_ratio: {e}")
        anchor_diff_ratio = 0.0

    return anchor_tags_count, anchor_empty_href_count, anchor_diff_count, anchor_diff_ratio


#####################3-link_count#############################
# <script> attr-> src =,<meta> attr - content,<links> tag ,attr - href=
#here i divided the big function into 4 smaller ones for each component
def count_external_script_src(script_list: list, base_domain: str) -> tuple:
    external_script_count = 0
    sus_words_in_script = 0

    for tag in script_list:
        try:
            src= safe_extract(tag, "src")
            if not src:
                continue

            domain = normalize_domain(src)
            if not domain:
                continue

            if domain != base_domain:
                external_script_count += 1

            matches = SUSPICIOUS_WORDS_REGEX.findall(src.lower())
            sus_words_in_script += len(matches)

        except Exception as e:
            logging.error(f"[ERROR] Failed processing <script> tag: {e}")
            continue
    total_script_count = len(script_list)
    external_script_ratio=external_script_count/total_script_count if total_script_count>0 else 0.0
    return external_script_count, sus_words_in_script,external_script_ratio


def count_external_meta_content(meta_list: list, base_domain: str) -> tuple:
    external_meta_count = 0
    sus_words_in_meta = 0

    for tag in meta_list:
        try:
            value = safe_extract(tag, "content")
            if not value:
                continue

            domain = normalize_domain(value)
            if not domain:
                continue

            if domain != base_domain:
                external_meta_count += 1

            text = value
            if not text:
                continue

            matches = SUSPICIOUS_WORDS_REGEX.findall(text.lower())
            sus_words_in_meta += len(matches)

        except Exception as e:
            logging.error(f"[ERROR] Failed processing <meta> tag: {e}")
            continue
    total_meta_count = len(meta_list)
    external_meta_ratio = external_meta_count / total_meta_count if total_meta_count > 0 else 0.0
    return external_meta_count, sus_words_in_meta,external_meta_ratio


def count_external_link_href(link_list: list, base_domain: str) -> tuple:
    external_link_count = 0
    total_links = 0
    for tag in link_list:
        try:
            value = safe_extract(tag, "href")

            if not value:
                continue
            total_links += 1
            domain = normalize_domain(value)

            if not domain:
                continue

            if domain != base_domain:
                external_link_count += 1

        except Exception as e:
            logging.error(f"[ERROR] Failed processing <link> tag for external href: {e}")
            continue
    ratio_external_links =external_link_count / total_links if total_links > 0 else 0.0

    return total_links,external_link_count, ratio_external_links


def link_count_in_html(extern_links: int, extern_meta: int, extern_script: int) -> int:
    try:
        total_extern_links = extern_links + extern_meta + extern_script
        return total_extern_links
    except Exception as e:
        logging.error(f"[ERROR] Failed to calculate total external links: {e}")
        return -1

#####################4-request_url#############################
# tags--->    < img,source,audio,video,embed,iframe >, attr-> src

def extract_request_url_feature(resources_elements_list: list, base_domain: str) -> Tuple[float, float,float]:

    total_resources = len(resources_elements_list)
    external_count = 0
    try:

        for tag in resources_elements_list:
            try:
                src = safe_extract(tag, "src")
                if not src:
                    continue
                domain = normalize_domain(src)
                if not domain:
                    continue
                if domain != base_domain:
                    external_count += 1
            except Exception as e:
                logging.warning(f"[WARN] Failed to process resource tag: {e}")
                continue

    except Exception as e:
        logging.error(f"[ERROR] Failed to extract request_url features: {e}")
    external_request_ratio=external_count / total_resources if total_resources > 0 else 0.0
    return total_resources, external_count,external_request_ratio



#####################5-sfh#############################
# <form> tag ,attr - action/nothing=

def extract_sfh_feature(form_list: list, base_domain: str) -> tuple:

    sfh_count = len(form_list)
    sfh_action_is_blank = 0
    sfh_domain_not_the_same = 0
    password_in_sfh = 0
    has_suspicious_words = 0
    try:
        for form in form_list:
            try:
                action = safe_extract(form, "action")
                if not action or action.lower() in ["about:blank", "#", ""]:
                    sfh_action_is_blank += 1
                else:
                    action_domain = normalize_domain(action)
                    if action_domain and action_domain != base_domain:
                        sfh_domain_not_the_same += 1
            except Exception as e:
                logging.warning(f"[WARN] Failed to extract action from form: {e}")

            try:
                inputs = form.find_all("input")
                for i in inputs:
                    t = i.get("type", "").lower()
                    n = i.get("name", "").lower()
                    if t == "password":
                        password_in_sfh += 1
                    if any(w in n for w in cp.get_suspicious_keywords()):
                        has_suspicious_words += 1
            except Exception as e:
                logging.warning(f"[WARN] Failed to process inputs in form: {e}")

    except Exception as e:
        logging.error(f"[ERROR] Failed to extract sfh features: {e}")

    return sfh_count, sfh_action_is_blank, sfh_domain_not_the_same, password_in_sfh, has_suspicious_words

#####################6-iframe#############################
# <iframe> tag ,attr - src/srcdoc=

def extract_iframe_feature_src(frame_src_list: list, base_domain: str) -> tuple:
    iframe_src_count = 0
    iframe_src_style_hidden = 0
    iframe_src_size = 0
    iframe_src_domain_not_the_same = 0
    iframe_no_src_sendbox = 0

    for iframe in frame_src_list:
        try:
            src = iframe.get("src", "").strip().lower()
            if not src:
                continue

            if any(x in src for x in ["ads", "analytics", "pixel", "tracker", "doubleclick"]):
                continue

            iframe_src_count += 1

            domain = normalize_domain(src)
            if domain and domain != base_domain:
                iframe_src_domain_not_the_same += 1

            style = iframe.get("style", "").lower()
            if "display:none" in style or "visibility:hidden" in style:
                iframe_src_style_hidden += 1

            width = iframe.get("width", "").strip()
            height = iframe.get("height", "").strip()
            if width == "0" or height == "0":
                iframe_src_size += 1

            if not iframe.has_attr("sandbox"):
                iframe_no_src_sendbox += 1

        except Exception as e:
            logging.warning(f"[WARN] extract_iframe_feature_src failed: {e}")
            continue
    iframe_external_src_ratio=iframe_src_domain_not_the_same/iframe_src_count if iframe_src_count>0 else 0.0
    return (iframe_src_count, iframe_src_style_hidden, iframe_src_size,iframe_src_domain_not_the_same, iframe_no_src_sendbox,
            iframe_external_src_ratio)

def extract_iframe_feature_srcdoc(iframe_list: list, base_domain: str) -> tuple:
    iframe_srcdoc_count = 0
    iframe_src_doc_hidden = 0
    iframe_srcdoc_js_existence = 0
    iframe_srcdoc_sus_words = 0

    try:
        for iframe in iframe_list:
            try:
                srcdoc = iframe.get("srcdoc", "").strip().lower()
            except Exception:
                srcdoc = ""

            if not srcdoc:
                continue

            iframe_srcdoc_count += 1

            try:
                clean_srcdoc_text = BeautifulSoup(srcdoc, "html.parser").get_text().lower()
            except Exception:
                clean_srcdoc_text = ""

            try:
                if SUSPICIOUS_WORDS_REGEX.search(clean_srcdoc_text):
                    iframe_srcdoc_sus_words += 1
            except Exception:
                pass

            try:
                if "<script" in srcdoc or "javascript:" in srcdoc:
                    iframe_srcdoc_js_existence += 1
            except Exception:
                pass

            try:
                if "display:none" in srcdoc or "visibility:hidden" in srcdoc:
                    iframe_src_doc_hidden += 1
            except Exception:
                pass

    except Exception as e:
        logging.error(f"[ERROR] Failed to extract iframe srcdoc features: {e}")
    return iframe_srcdoc_count, iframe_src_doc_hidden, iframe_srcdoc_js_existence, iframe_srcdoc_sus_words


def total_iframe_src_n_doc(src_count:int,srcdoc_count:int)->int:
    return src_count+srcdoc_count

#####################7-suspicious_js#############################

def detect_suspicious_js_behavior(soup: BeautifulSoup, base_domain: str) -> tuple:
    inline_scripts_count=0
    high_risk_patterns_count=0
    medium_risk_patterns_count=0
    low_risk_patterns_count=0
    sus_js_domain_not_the_same=0

    try:
        inline_scripts = soup.find_all("script", src=False)
    except Exception:
        return inline_scripts_count,high_risk_patterns_count,medium_risk_patterns_count,low_risk_patterns_count,sus_js_domain_not_the_same
    inline_scripts_count=len(inline_scripts)

    for script in inline_scripts:
        try:
            content = script.get_text().strip().lower()
        except Exception:
            content = ""

        for pattern in cp.get_high_risk_patterns():
            if re.search(pattern, content):
                high_risk_patterns_count += 1

        for pattern in cp.get_medium_risk_patterns():
            if re.search(pattern, content):
                medium_risk_patterns_count += 1

        for pattern in cp.get_low_risk_patterns():
            if re.search(pattern, content):
                low_risk_patterns_count += 1

    try:
        external_scripts = soup.find_all("script", src=True)
        for script in external_scripts:
            src = safe_extract(script, "src")
            domain = normalize_domain(src)
            if domain and domain != base_domain and domain not in cp.get_known_safe_script_hosts():
                sus_js_domain_not_the_same += 1

    except Exception as e:
        logging.error(f"[ERROR] Problem reading link rel attribute: {e}")
    sus_js_behave_ratio= sus_js_domain_not_the_same/inline_scripts_count if inline_scripts_count>0 else 0.0
    risk_patterns_ratio=(high_risk_patterns_count+medium_risk_patterns_count+low_risk_patterns_count)/inline_scripts_count if inline_scripts_count>0 else 0.0
    return (inline_scripts_count, high_risk_patterns_count, medium_risk_patterns_count, low_risk_patterns_count, sus_js_domain_not_the_same
                ,sus_js_behave_ratio,risk_patterns_ratio)


#####################8-nlp#############################

def nlp_based_phishing_text_check(soup: BeautifulSoup) -> int:
    try:
        text = soup.get_text(strip=True).lower()
        matches = SUSPICIOUS_WORDS_REGEX.findall(text)
        return len(matches)
    except Exception as e:
        logging.error(f"[ERROR] Problem in detecting nlp text : {e}")
        return 0



#####################9-analyze_textual_tags#############################

def analyze_textual_tags(count_script:int,count_meta:int) -> int:
    return count_script + count_meta


##### to stage 3 full loaded html
####################10-dynamic_script#############################
def detect_script_counts(driver: webdriver, base_domain: str) -> Tuple[int, int]:
    try:
        total_scripts = driver.execute_script("return document.scripts.length;")

        external_scripts = driver.execute_script(f"""
            return [...document.scripts].filter(s => {{
                if (!s.src) return false;
                try {{
                    let domain = new URL(s.src).hostname;
                    return !domain.endsWith("{base_domain}");
                }} catch (e) {{
                    return false;
                }}
            }}).length;
        """)
        return total_scripts, external_scripts
    except Exception as e:
        logging.warning(f"[WARN] detect_script_counts failed: {e}")
        return 0, 0



#####################11-auto_redirect#############################
############## after all html was loaded
# this function is blocking because the waiting for full upload of the page ,
def detect_auto_redirect(driver: webdriver, base_domain: str, timeout: float = 3.0) ->tuple:
    meta_equiv=0
    window_or_replace_redirect=0
    autoredirect_different_domain=0
    try:
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

        page_source = driver.page_source.lower()
    except Exception:
        return meta_equiv,  window_or_replace_redirect, autoredirect_different_domain
    try:

        if re.search(r'<meta\s+http-equiv\s*=\s*["\']?refresh["\']?', page_source, re.IGNORECASE):
            meta_equiv=1
    except Exception:
        pass
    try:
        if re.search(r'(window\.)?location\.(href|replace)', page_source):
            window_or_replace_redirect=1
    except Exception:
        pass
    try:
        final_url = driver.current_url

        if normalize_domain(final_url) != base_domain:
            autoredirect_different_domain=1

    except Exception:
        pass

    return meta_equiv, window_or_replace_redirect, autoredirect_different_domain



#####################12-login_form_visibility#############################
def check_login_form_visibility(driver: webdriver) -> int:
    try:
        script = """
        var forms = document.getElementsByTagName('form');
        for (var i = 0; i < forms.length; i++) {
            var style = window.getComputedStyle(forms[i]);
            if (style.display === 'none' || style.visibility === 'hidden' ||
                forms[i].offsetWidth === 0 || forms[i].offsetHeight === 0) {
                return 1;
            }
        }
        return 0;
        """
        result = driver.execute_script(script)
        return int(result)
    except Exception as e:
        logging.warning(f"[WARN] check_login_form_visibility failed: {e}")
        return 0

#####################13-onmouseover#############################
def detect_onmouseover_in_dom(soup: BeautifulSoup) -> tuple:
    tags_with_onmouseover_count=0
    suspicious_script_detected=0
    try:
        tags_with_onmouseover = soup.find_all(attrs={"onmouseover": True})
        tags_with_onmouseover_count=  len(tags_with_onmouseover)
        inline_scripts = soup.find_all("script", src=False)
        suspicious_script_detected = sum(1 for script in inline_scripts if "onmouseover" in script.get_text().lower())
    except Exception:
        pass

    return suspicious_script_detected,tags_with_onmouseover_count

#####################14-right_click_block#############################
### when checking in browser return to original function because it is very sus
def detect_right_click_block(soup: BeautifulSoup) -> tuple:

    suspicious_script_count=0
    contextmenu_tags_count=0

    try:
        contextmenu_tags = soup.find_all(attrs={"oncontextmenu": True})
        contextmenu_tags_count=len(contextmenu_tags)
    except Exception:
        pass
    try:

        inline_scripts = soup.find_all("script", src=False)
        for script in inline_scripts:
            content = script.get_text().lower()

            if not content:
                continue

            if re.search(r"event\s*\.\s*button\s*==\s*2", content) or "contextmenu" in content:
                suspicious_script_count +=1
    except Exception as e:
        logging.error(f"[ERROR] Problem in detect_right_click_block: {e}")
    return suspicious_script_count,contextmenu_tags_count




def find_html_features_separated(soup: BeautifulSoup, url: str, feature_type: str, driver: webdriver): # need to add back as arument , driver: webdriver
    domain = normalize_domain(url)
    elements = []

    if feature_type == "favicon_check":
        elements = element_extraction_from_html(soup, tag="link", attribute="href")
        return favicon_check(elements, domain)

    elif feature_type == "url_anchor":
        elements = element_extraction_from_html(soup, tag="a", attribute="href")
        return extract_url_of_anchor_feature(elements, domain)

    elif feature_type == "links_in_tags":
        meta_elements = element_extraction_from_html(soup, tag="meta", attribute="content")
        script_elements = element_extraction_from_html(soup, tag="script", attribute="src")
        link_elements = element_extraction_from_html(soup, tag="link", attribute="href")
        extern_meta, sus_words_meta,external_meta_ratio = count_external_meta_content(meta_elements, domain)
        extern_script, sus_words_script,external_script_ratio = count_external_script_src(script_elements, domain)
        total_links, external_link_count, extern_link_ratio = count_external_link_href(link_elements, domain)
        total_extern = link_count_in_html(external_link_count, extern_meta, extern_script)
        return extern_meta, sus_words_meta, extern_script, sus_words_script, total_links, external_link_count, extern_link_ratio, total_extern

    elif feature_type == "request_sources_from_diff_url":
        for tag in ["img", "source", "audio", "video", "embed", "iframe"]:
            elements += element_extraction_from_html(soup, tag=tag, attribute="src")
        return extract_request_url_feature(elements, domain)

    elif feature_type == "sfh":
        elements = element_extraction_from_html(soup, tag="form")
        return extract_sfh_feature(elements, domain)

    elif feature_type == "iframe":
        iframe_elements = element_extraction_from_html(soup, tag="iframe")
        src_features = extract_iframe_feature_src(iframe_elements, domain)
        srcdoc_features = extract_iframe_feature_srcdoc(iframe_elements, domain)
        total_iframes = total_iframe_src_n_doc(src_features[0], srcdoc_features[0])
        return src_features + srcdoc_features + (total_iframes,)

    elif feature_type == "suspicious_js":
        return detect_suspicious_js_behavior(soup, domain)

    elif feature_type == "nlp_text":
        return (nlp_based_phishing_text_check(soup),)

    # elif feature_type == "analyze_textual_tags":
    #     meta_elements = element_extraction_from_html(soup, tag="meta", attribute="content")
    #     script_elements = element_extraction_from_html(soup, tag="script", attribute="src")
    #     count_meta, _ = count_external_meta_content(meta_elements, domain)
    #     count_script, _ = count_external_script_src(script_elements, domain)
    #     return analyze_textual_tags(count_script, count_meta)

    elif feature_type == "detect_scripts_count":
        return detect_script_counts(driver,domain)

    elif feature_type == "detect_auto_redirect":
        return detect_auto_redirect(driver, domain)

    elif feature_type == "check_login_form_visibility":
        return (check_login_form_visibility(driver),)

    elif feature_type == "detect_onmouseover_in_dom":
        return detect_onmouseover_in_dom(soup)

    elif feature_type == "detect_right_click_block":
        return detect_right_click_block(soup)

    return ()


def safe_get_driver():
        options = Options()
        options.add_argument("--headless")
      #  options.binary_location="/usr/bin/firefox"
        return webdriver.Firefox(options=options)

def extract_stage3_features_debug_separated(input_csv_path, output_csv_path, pid):

    df = pd.read_csv(input_csv_path)
    total = len(df)
    results = []

    driver = safe_get_driver()

    for index, row in df.iterrows():
        url = row['URL']
        label = row.get('label', 0)
        print(f"\nproc num: {pid}🔍 [{index+1}/{total}] Processing URL: {url}")

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        success = False

        for trys in range(1):
            try:
                driver.get(url)
                WebDriverWait(driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
                html = driver.page_source
                # html = requests.get(url, timeout=3).text
                if not html:
                    raise Exception("Empty page source")

                soup = BeautifulSoup(html, "html.parser")
                features = [url]

                feature_types = [
                    "favicon_check",
                    "url_anchor",
                    "links_in_tags",
                    "request_sources_from_diff_url",
                    "sfh",
                    "iframe",
                    "suspicious_js",
                    "nlp_text",
                    # "analyze_textual_tags",
                    # "detect_scripts_count",
                    # "detect_auto_redirect",
                    # "check_login_form_visibility",
                    "detect_onmouseover_in_dom",
                    "detect_right_click_block"
                ]

                for feature_type in feature_types:
                    try:
                        result = find_html_features_separated(soup, url, feature_type,driver) #need to add back the driver to this function
                        features.extend(result)
                    except Exception as e:
                        logging.error(f"[ERROR] {feature_type} failed for {url} → {e}")
                        features.extend([-999])

                features.append(label)
                results.append(features)
                success = True
                break

            except Exception as e:
                logging.error(f"[ERROR] Failed to process URL: {url} → {e}")
                logging.warning(f"[RECOVERY] Restarting browser after crash at index {index}")
                try:
                    driver.quit()
                except:
                    pass
                driver = safe_get_driver()
                continue

        if not success:
            logging.warning(f"[SKIP] URL failed after 2 attempts: {url}")


    try:
        driver.quit()
    except:
        pass

    headers = [
        "url",
        # favicon
        "has_icon", "favicon_diff_domain", "favicon_invalid_ext",
        # anchor
        "anchor_tags_present", "anchor_empty_href", "anchor_diff_domain","anchor_diff_ratio",
        # links
        "meta_external", "meta_sus_words","external_meta_ratio","script_external", "script_sus_words","external_script_ratio", "total_links", "external_link_count", "ratio_extern_link", "total_external",
        # request sources
        "total_resources", "external_resources","external_request_ratio",
        # sfh
        "sfh_total_forms", "sfh_blank_action", "sfh_diff_domain", "sfh_password_inputs", "sfh_suspicious_inputs",
        # iframe src
        "iframe_src_count", "iframe_src_hidden", "iframe_src_size", "iframe_src_diff_domain", "iframe_src_no_sandbox","iframe_external_src_ratio",
        # iframe srcdoc
        "iframe_srcdoc_count", "iframe_srcdoc_hidden", "iframe_srcdoc_scripts", "iframe_srcdoc_sus_words",
        # total iframes
        "total_iframes",
        # suspicious_js
        "inline_scripts", "high_risk_patterns", "medium_risk_patterns", "low_risk_patterns", "sus_js_diff_domain","sus_js_behave_ratio","risk_patterns_ratio",
        # nlp
        "nlp_suspicious_words",
        # analyze_textual_tags
        # "analyze_textual_sus_words",
        # dynamic script injection
       "total_scripts","external_script",
        # auto redirect
        # "meta_refresh_redirect", "window_location_redirect", "final_url_diff_domain",
        # hidden login forms
       "hidden_forms_count",
        # onmouseover
        "onmouseover_scripts", "onmouseover_tags",
        # right click block
        "right_click_scripts", "right_click_tags",
        # label
        "label"
    ]
    pd.DataFrame(results, columns=headers).to_csv(output_csv_path, index=False)
    logging.info(f"\n✅ Finished. CSV saved to: {output_csv_path}")


def process_single_file(input_csv_path, output_csv_path,pid):
    try:
        logging.info(f"🚀 Starting pid= {pid} for {input_csv_path}")
        extract_stage3_features_debug_separated(input_csv_path, output_csv_path,pid)
        logging.info(f"✅ Finished pid={pid} for {input_csv_path}")
    except Exception as e:
        logging.error(f"❌ Error in pid={pid} processing {input_csv_path}: {e}")



if __name__ == "__main__":
    PROJECT_ROOT = get_project_root()
    input_csv_path = os.path.join(PROJECT_ROOT)
    output_csv_path = os.path.join(PROJECT_ROOT)

    files = [
         (os.path.join(input_csv_path,  "TEST1.csv"),os.path.join(output_csv_path,  "phish_urls_part_1_TEST.csv"), "1"),
       # (os.path.join(input_csv_path, "phish_urls_part_2.csv"),os.path.join(output_csv_path, "phish_urls_part_2_output_full.csv"), "2"),
       # (os.path.join(input_csv_path, "phish_urls_part_3.csv"),os.path.join(output_csv_path, "phish_urls_part_3_output_full.csv"), "3"),
        #(os.path.join(input_csv_path, "phish_urls_part_4.csv"),os.path.join(output_csv_path, "phish_urls_part_4_output_full.csv"), "4"),
        # (os.path.join(input_csv_path, "phish_urls_part_5.csv"),os.path.join(output_csv_path, "phish_urls_part_5_output.csv"), "5"),
        # (os.path.join(input_csv_path, "phish_urls_part_6.csv"),os.path.join(output_csv_path, "phish_urls_part_6_output.csv"), "6"),
        # (os.path.join(input_csv_path, "phish_urls_part_7.csv"),os.path.join(output_csv_path, "phish_urls_part_7_output_full.csv"), "7"),
        # (os.path.join(input_csv_path, "phish_urls_part_8.csv"),os.path.join(output_csv_path, "phish_urls_part_8_output_full.csv"), "8")
    ]


    processes = []

    for input_csv, output_csv, id in files:
        p = Process(target=process_single_file, args=(input_csv, output_csv, id))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
        if p.exitcode != 0:
            print(f"⚠️ Process {p.pid} exited with code {p.exitcode}")
    print("✅✅✅ All processes finished!")

    print("🎯 All files processed successfully!\n")
