import { parse } from 'tldts';


console.log("🔥 Extension is running!");
document.body.style.border = "15px solid red";

// Variables
//let domain = window.location.hostname;
//console.log(domain);
let type_of_HTML = "";

console.log(getCleanDomain('https://www.google.com'));

// Get initial HTML (not async-safe)
function get_initial_html() {
  let HTML;

  if (document.readyState === "loading") {
    HTML = document.documentElement.outerHTML;
  } else {
    window.addEventListener("load", () => {
      HTML = document.documentElement.outerHTML;
    });
  }

  return HTML;
}

// Async-safe full HTML getter
function get_full_html() {
  return new Promise((resolve) => {
    if (document.readyState === "complete") {
      resolve(document.documentElement.outerHTML);
    } else {
      window.addEventListener("load", () => {
        resolve(document.documentElement.outerHTML);
      });
    }
  });
}

(async () => {
  const html = await get_full_html();
  console.log("🔥🔥🔥🔥🔥the html file🔥🔥🔥🔥🔥:");
  console.log(html);
  let check_login_res=check_login_form_visability()
  let js_login_res=check_login_res;
  console.log(js_login_res);
  let js_favicon_obj=favicon(html);
  console.log(js_favicon_obj);
  let links_in_tags_obj=links_in_tags(html);
  console.log(links_in_tags_obj);
  let extract_iframe_feature_src_obj=extract_iframe_feature_src(html);
  console.log(extract_iframe_feature_src_obj);
  let extract_iframe_feature_srcdoc_obj=extract_iframe_feature_srcdoc();
  console.log(extract_iframe_feature_srcdoc_obj);

})();

function favicon(domain)
{ let favicon_obj={}
  let favicon_diff_domain_count=0;
  let has_icon=0;
  let favicon_invalid_ending_count=0;
  let links=document.getElementsByTagName('link');
  let href_array= [];
  for (let index = 0; index < links.length; index++)
 {
    let rel =links[index].getAttribute('rel');
    let href =links[index].getAttribute('href');

    if (rel  &&  rel.toLowerCase().includes('icon')  &&  href)
    {
      href_array.push(href);
    }
  }
  has_icon = href_array.length > 0 ? 1 : 0;

  href_array.forEach(href =>
  {  
      if(!check_icon_link_end(href))
      {
        favicon_invalid_ending_count+=1;
      }
      let norm=normalize_domain(href);
      const favicon_domain = norm ? getCleanDomain(norm) : null;
      
      if (favicon_domain && favicon_domain!=domain)
      {
        favicon_diff_domain_count+=1;
      }
  });

  favicon_obj={
    has_icon,
    favicon_diff_domain_count,
    favicon_invalid_ending_count
  }
  return favicon_obj;
}


function check_icon_link_end(href_link)//string
{
const isValid = /\.(ico|png|gif)([\?#].*)?$/i.test(href_link);
return isValid;
}
function getCleanDomain(url) {
  const parsed = parse(url);
  return parsed.domain || null;
}

function normalize_domain(url)
{
  let a_domain=document.createElement('a');
  a_domain.href=url;
  return a_domain.hostname;
}

function generic_link_extractor_to_obj(domain,links_obj,tag,attr)
{ 
  let script_tags= document.getElementsByTagName(tag);
  get_links_out(links_obj,script_tags,attr,domain);
}


function get_links_out(link_obj,link_list,attribute,domain)
{
   for (let i = 0; i < link_list.length; i++)
  {
    let attribute_content = link_list[i].getAttribute(attribute);
    if(!attribute_content)
    {
      continue;
    }
    let con_domain=getCleanDomain(attribute_content);
    if (con_domain!=domain)
    {
        link_obj.external_count+=1;
    }
    let matches=countSuspiciousWords(attribute_content);
    link_obj.sus_words+=matches;
  }
 
    link_obj.external_ratio = link_list.length? link_obj.external_count / link_list.length : 0;
  
  return;

}
function total_extern_links_count(link_obj,script_obj,meta_obj)
{
  let total_external_count=link_obj.external_count+script_obj.external_count+meta_obj.external_count;
  return total_external_count;

}
function links_in_tags(domain)
{
let link_obj={external_count:0,sus_words:0, external_ratio:0};
let meta_obj={external_count:0,sus_words:0, external_ratio:0};
let script_obj={external_count:0,sus_words:0, external_ratio:0};
generic_link_extractor_to_obj(domain,link_obj,'link','href');
generic_link_extractor_to_obj(domain,script_obj,'script','src');
generic_link_extractor_to_obj(domain,meta_obj,'meta','content');
let total_external = total_extern_links_count(link_obj, script_obj,meta_obj);
return {
    link_obj,
    script_obj,
    meta_obj,
    total_external
  };
}
function extract_iframe_feature_src(domain)
{
  let iframe_src_count = 0
  let iframe_src_style_hidden = 0
  let iframe_src_size = 0
  let iframe_src_diff_domain = 0
  let iframe_no_sendbox = 0

  let iframe_list=document.getElementsByTagName('iframe');
  for (let i = 0; i < iframe_list.length; i++) {
    const iframe = iframe_list[i];

    let src  = iframe.getAttribute('src');
    if (!src )continue;

    src = src.trim().toLowerCase();

    if (check_advertise_content(src)) continue;

    iframe_src_count +=1;

    let norm=normalize_domain(src);
    const src_domain = norm ? getCleanDomain(norm) : null;
    if( src_domain&&src_domain!==domain)
    {
      iframe_src_diff_domain+=1;
    }

    if (check_style_anomalies(iframe)) {
      iframe_src_style_hidden += 1;
    }
     const width = iframe.getAttribute('width')?.trim();
    const height = iframe.getAttribute('height')?.trim();
    if (width === "0" || height === "0") {
      iframe_src_size += 1;
    }
     if (!iframe.hasAttribute("sandbox")) {
      iframe_no_sendbox += 1;
    }
    
  }
 const iframe_external_src_ratio =iframe_src_count > 0 ? iframe_src_diff_domain / iframe_src_count : 0;
  return {
    iframe_src_count,
    iframe_src_style_hidden,
    iframe_src_size,
    iframe_src_diff_domain,
    iframe_no_sendbox,
    iframe_external_src_ratio
  };


}

function extract_iframe_feature_srcdoc() {
  let iframe_srcdoc_count = 0;
  let iframe_src_doc_hidden = 0;
  let iframe_srcdoc_js_existence = 0;
  let iframe_srcdoc_sus_words = 0;

  const iframe_list = document.getElementsByTagName('iframe');

  for (let i = 0; i < iframe_list.length; i++) {
    const iframe = iframe_list[i];
    let srcdoc = "";

    try {
      srcdoc = iframe.getAttribute("srcdoc")?.trim().toLowerCase() || "";
    } catch (e) {
      srcdoc = "";
    }

    if (!srcdoc) continue;

    iframe_srcdoc_count += 1;
    const clean_srcdoc_text = srcdoc;

    if (/(log[\s\-]?in|sign[\s\-]?in|auth|user(name)?|email|phone|account|credential|password|passcode|pin|security[\s\-]?code|credit[\s\-]?card|cvv|expiry|iban|bank)/i.test(clean_srcdoc_text)) {
      iframe_srcdoc_sus_words += 1;
    }

    if (srcdoc.includes("<script") || srcdoc.includes("javascript:")) {
      iframe_srcdoc_js_existence += 1;
    }

    if (/display\s*:\s*none/i.test(srcdoc) || /visibility\s*:\s*hidden/i.test(srcdoc))
    {
       iframe_src_doc_hidden += 1;
    }

  }

  return {
    iframe_srcdoc_count,
    iframe_src_doc_hidden,
    iframe_srcdoc_js_existence,
    iframe_srcdoc_sus_words
  };
}

    
  

function countSuspiciousWords(text) {
  if (typeof text !== "string") return 0;

  const regex = /(log[\s\-]?in|sign[\s\-]?in|auth|user(name)?|email|phone|account|credential|password|passcode|pin|security[\s\-]?code|credit[\s\-]?card|cvv|expiry|iban|bank)/gi;
  const matches = text.toLowerCase().match(regex);

  return matches ? matches.length : 0;
}

// Function to check login form visibility
function check_login_form_visability() {
  let forms = document.getElementsByTagName('form');
  for (let i = 0; i < forms.length; i++) {
   return check_style_anomalies(forms[i]);
  }
}

function check_style_anomalies(tag) {
  const style = window.getComputedStyle(tag);
  return (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    tag.offsetWidth === 0 ||
    tag.offsetHeight === 0
  ) ? 1 : 0;
}

function check_advertise_content(src) {
  if (typeof src !== "string") return false;
  const keywords = ["ads", "analytics", "pixel", "tracker", "doubleclick"];
  return keywords.some(word => src.toLowerCase().includes(word));
}
