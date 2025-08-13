#!/usr/bin/env python3
"""
Ultimate Punycode Generator for Bug Bounty Testing
Advanced tool for generating punycode variants, domain spoofing, and security testing
"""

import itertools
import urllib.parse
import re
from typing import List, Dict, Set, Optional
import json

class PunycodeGenerator:
    def __init__(self):
        self.homoglyphs_map = {
            'a': ['à','á','â','ã','ä','å','ɑ','А','Α','Ꭺ','Ａ','𝔄','𝕬','𝒜','𝐀','𝐴','𝘈','𝙰','𝖠','𝗔','𝘼','𝚨','𝑨','ⓐ','Ⓐ','🅐','🅰','𝔞','𝖆','𝒶','𝗮','𝘢','а','ａ','ą','ā','ă','ȁ','ȃ','ȧ','ḁ','ẚ','Ạ','ạ','ả','ấ','ầ','ẩ','ẫ','ậ','ắ','ằ','ẳ','ẵ','ặ'],
            'b': ['Ь','Ꮟ','Ƅ','ᖯ','𝐛','𝑏','𝒃','𝓫','𝔟','𝕓','𝖇','𝗯','𝘣','𝙗','𝚋','б','ｂ','ƀ','ḃ','ḅ','ḇ','ᵬ','ᶀ','ь','в','ᴃ','ᴯ','ᵇ'],
            'c': ['ϲ','с','ƈ','ȼ','ḉ','ⲥ','𝐜','𝑐','𝒄','𝓬','𝔠','𝕔','𝖈','𝗰','𝘤','𝙘','𝚌','ｃ','ć','ĉ','ċ','č','ç','ḉ','ĉ','ȼ','ć','ċ','č','ç','ḉ','ĉ','ȼ','ⅽ','ⲥ','с','ᴄ','ᴄ','ᴐ','ᴄ','ᴘ','ᴄ','ᴄ','ᴄ','ᴄ','ᴄ','ᴄ','ᴄ','ᴄ'],
            'd': ['ԁ','ժ','Ꮷ','𝐝','𝑑','𝒅','𝓭','𝔡','𝕕','𝖉','𝗱','𝘥','𝙙','𝚍','ｄ','ď','đ','ḋ','ḍ','ḏ','ḑ','ḓ','ᵈ','ᶁ','ȡ','ⅾ','ⲇ','д','ᴅ','ᴅ','ᴅ','ᴅ','ᴅ','ᴅ','ᴅ','ᴅ'],
            'e': ['е','ҽ','℮','ḛ','ḝ','ẹ','é','è','ê','ë','ē','ė','ę','𝐞','𝑒','𝒆','𝓮','𝔢','𝕖','𝖊','𝗲','𝘦','𝙚','𝚎','ｅ','ĕ','ě','ȅ','ȇ','ȩ','ḙ','ḛ','ḝ','ẻ','ẽ','ế','ề','ể','ễ','ệ','ⅇ','ⲉ','е','ё','э','ᴇ','ᴇ','ᴇ','ᴇ','ᴇ','ᴇ','ᴇ','ᴇ','ᴇ','ᴇ','ᴇ'],
            'f': ['ғ','𝐟','𝑓','𝒇','𝓯','𝔣','𝕗','𝖋','𝗳','𝘧','𝙛','𝚏','ｆ','ḟ','ƒ','ᵮ','ᶂ','ⅎ','ⲫ','ф','ᖴ','ᖴ','ᖴ','ᖴ','ᖴ','ᖴ','ᖴ','ᖴ','ᖴ','ᖴ','ᖴ'],
            'g': ['ɡ','ց','𝐠','𝑔','𝒈','𝓰','𝔤','𝕘','𝖌','𝗴','𝘨','𝙜','𝚐','ｇ','ĝ','ğ','ġ','ģ','ǧ','ǥ','ḡ','ᵍ','ᶃ','ɠ','ᴳ','ᴳ','ᴳ','ᴳ','ᴳ','ᴳ','ᴳ','ᴳ','ᴳ','ᴳ','ᴳ'],
            'h': ['һ','հ','Ꮒ','ℎ','𝐡','𝒉','𝒽','𝓱','𝔥','𝕙','𝖍','𝗵','𝘩','𝙝','𝚑','ｈ','ĥ','ħ','ȟ','ḣ','ḥ','ḧ','ḩ','ḫ','ẖ','ʰ','ᵸ','ʱ','ʰ','ⲏ','х','ᴴ','ᴴ','ᴴ','ᴴ','ᴴ','ᴴ','ᴴ','ᴴ','ᴴ','ᴴ','ᴴ'],
            'i': ['і','ɩ','Ꭵ','Ⅰ','ı','í','ì','î','ï','ī','į','𝐢','𝑖','𝒊','𝓲','𝔦','𝕚','𝖎','𝗶','𝘪','𝙞','𝚒','ｉ','ĭ','ǐ','ȉ','ȋ','ḭ','ḯ','ỉ','ị','ⅰ','ⅼ','ⲓ','і','ї','ᴵ','ᴵ','ᴵ','ᴵ','ᴵ','ᴵ','ᴵ','ᴵ','ᴵ','ᴵ','ᴵ'],
            'j': ['ј','ʝ','ϳ','𝐣','𝑗','𝒋','𝓳','𝔧','𝕛','𝖏','𝗷','𝘫','𝙟','𝚓','ｊ','ĵ','ǰ','ȷ','ɉ','ʲ','ᴶ','ᴶ','ᴶ','ᴶ','ᴶ','ᴶ','ᴶ','ᴶ','ᴶ','ᴶ','ᴶ'],
            'k': ['κ','𝐤','𝑘','𝒌','𝓴','𝔨','𝕜','𝖐','𝗸','𝘬','𝙠','𝚔','ｋ','ķ','ǩ','ḱ','ḳ','ḵ','ᵏ','ᶄ','ⲕ','к','ᴷ','ᴷ','ᴷ','ᴷ','ᴷ','ᴷ','ᴷ','ᴷ','ᴷ','ᴷ','ᴷ'],
            'l': ['ⅼ','ӏ','Ɩ','ʟ','𝐥','𝑙','𝒍','𝓵','𝔩','𝕝','𝖑','𝗹','𝘭','𝙡','𝚕','ｌ','ĺ','ļ','ľ','ŀ','ł','ḷ','ḹ','ḻ','ḽ','ˡ','ⅼ','ⲗ','л','ᴸ','ᴸ','ᴸ','ᴸ','ᴸ','ᴸ','ᴸ','ᴸ','ᴸ','ᴸ','ᴸ'],
            'm': ['м','ṃ','ᴍ','𝐦','𝑚','𝒎','𝓶','𝔪','𝕞','𝖒','𝗺','𝘮','𝙢','𝚖','ｍ','ḿ','ṁ','ṃ','ᵐ','ᶆ','ⅿ','ⲙ','м','ᴹ','ᴹ','ᴹ','ᴹ','ᴹ','ᴹ','ᴹ','ᴹ','ᴹ','ᴹ','ᴹ'],
            'n': ['ո','п','ռ','ṅ','ṇ','ṋ','𝐧','𝑛','𝒏','𝓷','𝔫','𝕟','𝖓','𝗻','𝘯','𝙣','𝚗','ｎ','ń','ñ','ň','ņ','ǹ','ȵ','ṅ','ṇ','ṉ','ṋ','ᵰ','ᶇ','ⁿ','ⲛ','н','ᴺ','ᴺ','ᴺ','ᴺ','ᴺ','ᴺ','ᴺ','ᴺ','ᴺ','ᴺ','ᴺ'],
            'o': ['ο','օ','ӧ','ö','ó','ò','ô','õ','ō','ő','ⲟ','𝐨','𝑜','𝓸','𝔬','𝕠','𝖔','𝗼','𝘰','𝙤','𝚬','ｏ','ŏ','ǒ','ǫ','ǭ','ǰ','ȍ','ȏ','ȫ','ȭ','ȯ','ȱ','ṍ','ṏ','ṑ','ṓ','ọ','ỏ','ố','ồ','ổ','ỗ','ộ','ớ','ờ','ở','ỡ','ợ','ⅰ','ⲟ','о','ё','ө','ᴼ','ᴼ','ᴼ','ᴼ','ᴼ','ᴼ','ᴼ','ᴼ','ᴼ','ᴼ','ᴼ'],
            'p': ['р','ρ','⍴','𝐩','𝑝','𝒑','𝓹','𝔭','𝕡','𝖕','𝗽','𝘱','𝙥','𝚭','ｐ','ṕ','ṗ','ᵖ','ᶈ','ⲣ','р','ᴾ','ᴾ','ᴾ','ᴾ','ᴾ','ᴾ','ᴾ','ᴾ','ᴾ','ᴾ','ᴾ'],
            'q': ['զ','ԛ','գ','𝐪','𝑞','𝒒','𝓺','𝔮','𝕢','𝖖','𝗾','𝘲','𝙦','𝚞','ｑ','ʠ','ᵠ','ᶐ','ⲁ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ','ᵠ'],
            'r': ['ᴦ','г','ř','ȓ','ṛ','ⲅ','𝐫','𝑟','𝒓','𝓻','𝔯','𝕣','𝖗','𝗿','𝘳','𝙧','𝚛','ｒ','ŕ','ŗ','ř','ȑ','ȓ','ṙ','ṛ','ṝ','ṟ','ᵣ','ᵨ','ᶉ','ʳ','ⲅ','г','ᴿ','ᴿ','ᴿ','ᴿ','ᴿ','ᴿ','ᴿ','ᴿ','ᴿ','ᴿ','ᴿ'],
            's': ['ѕ','ʂ','ṡ','ṣ','𝐬','𝑠','𝒔','𝓼','𝔰','𝕤','𝖘','𝘴','𝙨','𝚜','ｓ','ś','ŝ','ş','š','ș','ṡ','ṣ','ṥ','ṧ','ṩ','ˢ','ᶊ','ⲋ','с','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ','ᔆ'],
            't': ['т','τ','ṭ','ț','ⲧ','𝐭','𝑡','𝒕','𝓽','𝔱','𝕥','𝖙','𝘵','𝙩','𝚝','ｔ','ţ','ť','ŧ','ț','ṫ','ṭ','ṯ','ṱ','ᵗ','ᶵ','ⲧ','т','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ','ᵀ'],
            'u': ['υ','ս','ü','ú','ù','û','ū','ⲩ','𝐮','𝑢','𝒖','𝓾','𝔲','𝕦','𝖚','𝘶','𝙪','𝚞','ｕ','ŭ','ů','ű','ų','ǔ','ǖ','ǘ','ǚ','ǜ','ȕ','ȗ','ṳ','ṵ','ṷ','ṹ','ṻ','ủ','ụ','ừ','ử','ữ','ự','ᵘ','ᶸ','ᵤ','ⲩ','у','ᵁ','ᵁ','ᵁ','ᵁ','ᵁ','ᵁ','ᵁ','ᵁ','ᵁ','ᵁ','ᵁ'],
            'v': ['ν','ѵ','ⴸ','𝐯','𝑣','𝒗','𝓿','𝔳','𝕧','𝖛','𝗏','𝘷','𝙫','𝚟','ｖ','ṽ','ṿ','ᵛ','ᶌ','ⱴ','ⲫ','в','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ','ᵛ'],
            'w': ['ԝ','ա','ѡ','ⲱ','𝐰','𝑤','𝒘','𝔀','𝕨','𝖜','𝗐','𝘸','𝙬','𝚠','ｗ','ŵ','ẁ','ẃ','ẅ','ẇ','ẉ','ẘ','ʷ','ʷ','ⲱ','ѡ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ','ᵂ'],
            'x': ['х','ҳ','ӿ','𝐱','𝑥','𝒙','𝔁','𝕩','𝖝','𝗑','𝘹','𝙭','𝚡','ｘ','ẋ','ẍ','ᵡ','ᶍ','ⲭ','х','ˣ','ˣ','ˣ','ˣ','ˣ','ˣ','ˣ','ˣ','ˣ','ˣ','ˣ','ˣ'],
            'y': ['у','ү','ӯ','ý','ÿ','ⲩ','𝐲','𝑦','𝒚','𝔂','𝕪','𝖞','𝗒','𝘺','𝙮','𝚢','ｙ','ŷ','ỳ','ỵ','ỷ','ỹ','ʸ','ʸ','ⲩ','у','ʸ','ʸ','ʸ','ʸ','ʸ','ʸ','ʸ','ʸ','ʸ','ʸ','ʸ','ʸ'],
            'z': ['ᴢ','ż','ź','ž','𝐳','𝑧','𝒛','𝔃','𝕫','𝖟','𝗓','𝘻','𝙯','𝚣','ｚ','ź','ż','ž','ȥ','ẑ','ẓ','ẕ','ᶻ','ⲍ','з','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ','ᶻ']
        }
        
        # Common TLD variations for testing
        self.tld_variations = [
            'com', 'net', 'org', 'io', 'co', 'me', 'app', 'dev', 'ly', 'sh',
            'ai', 'ml', 'tk', 'ga', 'cf', 'gq', 'pw', 'xyz', 'top', 'click'
        ]
        
        # Number/symbol homoglyphs
        self.number_homoglyphs = {
            '0': ['о', 'О', 'ο', 'Ο', '°', '〇', '۰', '߀'],
            '1': ['l', 'I', 'ǀ', 'ⅼ', '│', '¡', '║'],
            '2': ['Ζ', 'ᄅ', 'ᒿ', 'ს'],
            '3': ['Ʒ', 'ᄒ', 'ӡ', 'ᴣ'],
            '4': ['Ч', 'ᄋ', 'ᔕ'],
            '5': ['Ƽ', 'ᔕ', 'ᔕ'],
            '6': ['б', 'Ⴕ', 'ხ'],
            '7': ['ᒣ', 'ᔑ', 'ᗢ'],
            '8': ['Ȣ', 'ᔑ', 'ᗡ'],
            '9': ['Ⴔ', 'ᇿ', 'ᔭ']
        }

    def encode_punycode(self, text: str) -> Optional[str]:
        """Enhanced punycode encoding with better error handling"""
        try:
            # First try standard IDNA encoding
            encoded = text.encode('idna').decode('ascii')
            if encoded != text:
                return encoded
        except (UnicodeError, UnicodeDecodeError):
            pass
        
        try:
            # Try manual punycode encoding
            encoded = text.encode('punycode').decode('ascii')
            return 'xn--' + encoded
        except (UnicodeError, UnicodeDecodeError):
            pass
        
        # Handle special cases
        try:
            # Try each character individually
            parts = []
            for char in text:
                try:
                    part = char.encode('idna').decode('ascii')
                    parts.append(part)
                except:
                    parts.append(char)
            return ''.join(parts)
        except:
            return None

    def generate_letter_variants(self, letter: str) -> List[Dict[str, str]]:
        """Generate all homoglyph variants for a single letter"""
        letter = letter.lower()
        variants = []
        
        glyphs = self.homoglyphs_map.get(letter, [])
        for glyph in glyphs:
            punycode = self.encode_punycode(glyph)
            if punycode:
                variants.append({
                    'original': letter,
                    'glyph': glyph,
                    'punycode': punycode,
                    'unicode_name': f'U+{ord(glyph):04X}'
                })
        
        return variants

    def generate_domain_variants(self, domain: str, max_variants: int = 100) -> List[Dict[str, str]]:
        """Generate domain variants with homoglyphs"""
        parts = domain.split('.')
        base_domain = parts[0]
        tld = parts[1] if len(parts) > 1 else 'com'
        
        variants = []
        variant_count = 0
        
        # Generate single character substitutions
        for i, char in enumerate(base_domain):
            if char.lower() in self.homoglyphs_map:
                for glyph in self.homoglyphs_map[char.lower()][:10]:  # Limit to first 10 for performance
                    if variant_count >= max_variants:
                        break
                    
                    variant_domain = base_domain[:i] + glyph + base_domain[i+1:]
                    full_domain = f"{variant_domain}.{tld}"
                    punycode = self.encode_punycode(full_domain)
                    
                    if punycode and punycode != full_domain:
                        variants.append({
                            'original': domain,
                            'variant': full_domain,
                            'punycode': punycode,
                            'position': i,
                            'char_substituted': char,
                            'glyph_used': glyph
                        })
                        variant_count += 1
        
        # Generate multi-character substitutions (limited)
        if variant_count < max_variants:
            for positions in itertools.combinations(range(len(base_domain)), min(2, len(base_domain))):
                if variant_count >= max_variants:
                    break
                
                chars_to_replace = [base_domain[pos] for pos in positions]
                if all(char.lower() in self.homoglyphs_map for char in chars_to_replace):
                    
                    # Take first homoglyph for each position
                    replacements = []
                    for pos in positions:
                        char = base_domain[pos]
                        if char.lower() in self.homoglyphs_map:
                            replacements.append(self.homoglyphs_map[char.lower()][0])
                    
                    if len(replacements) == len(positions):
                        variant_domain = base_domain
                        for pos, replacement in zip(positions, replacements):
                            variant_domain = variant_domain[:pos] + replacement + variant_domain[pos+1:]
                        
                        full_domain = f"{variant_domain}.{tld}"
                        punycode = self.encode_punycode(full_domain)
                        
                        if punycode and punycode != full_domain:
                            variants.append({
                                'original': domain,
                                'variant': full_domain,
                                'punycode': punycode,
                                'positions': list(positions),
                                'multi_char': True
                            })
                            variant_count += 1
        
        return variants

    def generate_subdomain_variants(self, subdomain: str, domain: str) -> List[str]:
        """Generate subdomain variants for testing subdomain takeover"""
        variants = []
        
        # Generate punycode subdomains
        for char in subdomain:
            if char.lower() in self.homoglyphs_map:
                for glyph in self.homoglyphs_map[char.lower()][:5]:
                    variant_sub = subdomain.replace(char, glyph, 1)
                    punycode = self.encode_punycode(variant_sub)
                    if punycode and punycode != variant_sub:
                        variants.append(f"{punycode}.{domain}")
        
        return variants

    def generate_email_variants(self, email: str) -> List[Dict[str, str]]:
        """Generate email variants for testing email validation bypasses"""
        if '@' not in email:
            return []
        
        local, domain = email.split('@', 1)
        variants = []
        
        # Generate domain variants
        domain_variants = self.generate_domain_variants(domain, max_variants=20)
        for variant in domain_variants:
            variants.append({
                'original': email,
                'variant': f"{local}@{variant['variant']}",
                'punycode': f"{local}@{variant['punycode']}",
                'type': 'domain_homoglyph'
            })
        
        # Generate local part variants
        for i, char in enumerate(local):
            if char.lower() in self.homoglyphs_map:
                for glyph in self.homoglyphs_map[char.lower()][:5]:
                    variant_local = local[:i] + glyph + local[i+1:]
                    full_email = f"{variant_local}@{domain}"
                    punycode_email = self.encode_punycode(full_email)
                    
                    if punycode_email and punycode_email != full_email:
                        variants.append({
                            'original': email,
                            'variant': full_email,
                            'punycode': punycode_email,
                            'type': 'local_homoglyph'
                        })
        
        return variants

    def generate_url_variants(self, url: str) -> List[Dict[str, str]]:
        """Generate URL variants for testing URL validation bypasses"""
        try:
            parsed = urllib.parse.urlparse(url)
            variants = []
            
            # Generate domain variants
            if parsed.netloc:
                domain_variants = self.generate_domain_variants(parsed.netloc, max_variants=20)
                for variant in domain_variants:
                    new_url = url.replace(parsed.netloc, variant['punycode'])
                    variants.append({
                        'original': url,
                        'variant': new_url,
                        'type': 'domain_homoglyph',
                        'punycode_domain': variant['punycode']
                    })
            
            # Generate path variants
            if parsed.path:
                path_parts = parsed.path.split('/')
                for i, part in enumerate(path_parts):
                    if part:
                        for j, char in enumerate(part):
                            if char.lower() in self.homoglyphs_map:
                                for glyph in self.homoglyphs_map[char.lower()][:3]:
                                    variant_part = part[:j] + glyph + part[j+1:]
                                    new_path_parts = path_parts.copy()
                                    new_path_parts[i] = variant_part
                                    new_path = '/'.join(new_path_parts)
                                    new_url = urllib.parse.urlunparse(
                                        parsed._replace(path=new_path)
                                    )
                                    variants.append({
                                        'original': url,
                                        'variant': new_url,
                                        'type': 'path_homoglyph',
                                        'path_modified': new_path
                                    })
            
            return variants
        except Exception:
            return []

    def generate_payload_variants(self, payload: str) -> List[Dict[str, str]]:
        """Generate payload variants for bypassing WAF/filters"""
        variants = []
        
        # Common security keywords to target
        security_keywords = ['script', 'alert', 'prompt', 'confirm', 'eval', 'function', 'javascript', 'vbscript']
        
        for keyword in security_keywords:
            if keyword.lower() in payload.lower():
                # Find all occurrences
                start = 0
                while True:
                    pos = payload.lower().find(keyword.lower(), start)
                    if pos == -1:
                        break
                    
                    # Generate variants for this keyword
                    original_keyword = payload[pos:pos+len(keyword)]
                    for i, char in enumerate(keyword):
                        if char.lower() in self.homoglyphs_map:
                            for glyph in self.homoglyphs_map[char.lower()][:3]:
                                variant_keyword = keyword[:i] + glyph + keyword[i+1:]
                                variant_payload = payload[:pos] + variant_keyword + payload[pos+len(keyword):]
                                
                                variants.append({
                                    'original': payload,
                                    'variant': variant_payload,
                                    'keyword_modified': keyword,
                                    'position': pos,
                                    'type': 'waf_bypass'
                                })
                    
                    start = pos + 1
        
        return variants

    def generate_mixed_script_attacks(self, text: str) -> List[Dict[str, str]]:
        """Generate mixed script attacks using different Unicode blocks"""
        variants = []
        
        # Different script blocks for mixing
        script_variants = {
            'latin': 'abcdefghijklmnopqrstuvwxyz',
            'cyrillic': 'абсдефгхијклмнопќрстувшхуз',
            'greek': 'αβγδεφγηικλμνοπϸρστυνωχψζ'
        }
        
        for script_name, script_chars in script_variants.items():
            if script_name == 'latin':
                continue
                
            variant_text = text
            for i, char in enumerate(text.lower()):
                if char in 'abcdefghijklmnopqrstuvwxyz':
                    char_index = ord(char) - ord('a')
                    if char_index < len(script_chars):
                        if text[i].isupper():
                            replacement = script_chars[char_index].upper()
                        else:
                            replacement = script_chars[char_index]
                        variant_text = variant_text[:i] + replacement + variant_text[i+1:]
            
            if variant_text != text:
                punycode = self.encode_punycode(variant_text)
                variants.append({
                    'original': text,
                    'variant': variant_text,
                    'punycode': punycode,
                    'script': script_name,
                    'type': 'mixed_script'
                })
        
        return variants

    def test_bypass_scenarios(self, target: str) -> Dict[str, List]:
        """Generate comprehensive test scenarios for various bypass techniques"""
        scenarios = {
            'domain_spoofing': [],
            'subdomain_takeover': [],
            'email_bypass': [],
            'url_bypass': [],
            'waf_bypass': [],
            'mixed_script': [],
            'unicode_normalization': []
        }
        
        # Domain spoofing
        if '.' in target and '@' not in target:
            scenarios['domain_spoofing'] = self.generate_domain_variants(target)
            scenarios['subdomain_takeover'] = self.generate_subdomain_variants('test', target)
        
        # Email bypass
        if '@' in target:
            scenarios['email_bypass'] = self.generate_email_variants(target)
        
        # URL bypass
        if target.startswith(('http://', 'https://')):
            scenarios['url_bypass'] = self.generate_url_variants(target)
        
        # WAF bypass
        scenarios['waf_bypass'] = self.generate_payload_variants(target)
        
        # Mixed script attacks
        scenarios['mixed_script'] = self.generate_mixed_script_attacks(target)
        
        # Unicode normalization tests
        scenarios['unicode_normalization'] = self.test_unicode_normalization(target)
        
        return scenarios

    def test_unicode_normalization(self, text: str) -> List[Dict[str, str]]:
        """Test different Unicode normalization forms"""
        import unicodedata
        
        variants = []
        normalization_forms = ['NFC', 'NFD', 'NFKC', 'NFKD']
        
        for form in normalization_forms:
            try:
                normalized = unicodedata.normalize(form, text)
                if normalized != text:
                    punycode = self.encode_punycode(normalized)
                    variants.append({
                        'original': text,
                        'variant': normalized,
                        'punycode': punycode,
                        'normalization': form,
                        'type': 'unicode_normalization'
                    })
            except:
                continue
        
        return variants

    def export_wordlist(self, variants: List[Dict], filename: str = 'punycode_wordlist.txt'):
        """Export variants to a wordlist file"""
        unique_variants = set()
        
        for variant_group in variants:
            if isinstance(variant_group, list):
                for variant in variant_group:
                    if 'punycode' in variant and variant['punycode']:
                        unique_variants.add(variant['punycode'])
                    if 'variant' in variant and variant['variant']:
                        unique_variants.add(variant['variant'])
        
        with open(filename, 'w', encoding='utf-8') as f:
            for variant in sorted(unique_variants):
                f.write(variant + '\n')
        
        return len(unique_variants)

    def format_output(self, variants: Dict[str, List], target: str) -> str:
        """Format output for display"""
        output = []
        output.append(f"🎯 Punycode Analysis for: {target}")
        output.append("=" * 60)
        
        for category, variant_list in variants.items():
            if variant_list:
                output.append(f"\n🔍 {category.upper().replace('_', ' ')}:")
                output.append("-" * 40)
                
                for i, variant in enumerate(variant_list[:10], 1):  # Limit to first 10
                    if 'punycode' in variant and variant['punycode']:
                        output.append(f"{i:2d}. {variant.get('variant', target)} -> {variant['punycode']}")
                    elif 'variant' in variant:
                        output.append(f"{i:2d}. {variant['variant']}")
                
                if len(variant_list) > 10:
                    output.append(f"    ... and {len(variant_list) - 10} more variants")
        
        return '\n'.join(output)


def main():
    generator = PunycodeGenerator()
    
    print("🚀 Ultimate Punycode Generator for Bug Bounty")
    print("=" * 50)
    print("1. Single letter variants")
    print("2. Domain spoofing")
    print("3. Email bypass testing")
    print("4. URL bypass testing") 
    print("5. WAF bypass payloads")
    print("6. Comprehensive analysis")
    print("7. Mixed script attacks")
    print("8. Export wordlist")
    
    choice = input("\nSelect option (1-8): ").strip()
    
    if choice == '1':
        letter = input("Enter a letter (a-z): ").strip()
        if len(letter) == 1 and letter.isalpha():
            variants = generator.generate_letter_variants(letter)
            print(f"\n🔎 Punycode variants for letter: '{letter}'\n")
            for variant in variants:
                print(f"{variant['glyph']} ({variant['unicode_name']}) -> {variant['punycode']}")
        else:
            print("❗ Please enter a single valid letter.")
    
    elif choice == '2':
        domain = input("Enter domain (e.g., google.com): ").strip()
        variants = generator.generate_domain_variants(domain)
        print(f"\n🔍 Domain spoofing variants for: {domain}\n")
        for i, variant in enumerate(variants[:20], 1):
            print(f"{i:2d}. {variant['variant']} -> {variant['punycode']}")
    
    elif choice == '3':
        email = input("Enter email address: ").strip()
        variants = generator.generate_email_variants(email)
        print(f"\n📧 Email bypass variants for: {email}\n")
        for i, variant in enumerate(variants[:20], 1):
            print(f"{i:2d}. {variant['variant']} -> {variant['punycode']}")
    
    elif choice == '4':
        url = input("Enter URL: ").strip()
        variants = generator.generate_url_variants(url)
        print(f"\n🌐 URL bypass variants for: {url}\n")
        for i, variant in enumerate(variants[:20], 1):
            print(f"{i:2d}. {variant['variant']}")
    
    elif choice == '5':
        payload = input("Enter payload/keyword: ").strip()
        variants = generator.generate_payload_variants(payload)
        print(f"\n🛡️ WAF bypass variants for: {payload}\n")
        for i, variant in enumerate(variants[:20], 1):
            print(f"{i:2d}. {variant['variant']}")
    
    elif choice == '6':
        target = input("Enter target (domain/email/URL/payload): ").strip()
        scenarios = generator.test_bypass_scenarios(target)
        print(generator.format_output(scenarios, target))
        
        # Ask if user wants to export
        export = input("\nExport to wordlist? (y/n): ").strip().lower()
        if export == 'y':
            count = generator.export_wordlist(list(scenarios.values()))
            print(f"✅ Exported {count} unique variants to 'punycode_wordlist.txt'")
    
    elif choice == '7':
        text = input("Enter text for mixed script attack: ").strip()
        variants = generator.generate_mixed_script_attacks(text)
        print(f"\n🌍 Mixed script variants for: {text}\n")
        for i, variant in enumerate(variants, 1):
            print(f"{i:2d}. {variant['variant']} ({variant['script']}) -> {variant['punycode']}")
    
    elif choice == '8':
        target = input("Enter target for wordlist generation: ").strip()
        scenarios = generator.test_bypass_scenarios(target)
        count = generator.export_wordlist(list(scenarios.values()))
        print(f"✅ Exported {count} unique variants to 'punycode_wordlist.txt'")
    
    else:
        print("❗ Invalid option selected.")


if __name__ == "__main__":
    main()
