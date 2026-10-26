"""Small coloured marks for the notification services (Discord, Slack, Teams, ...), drawn from SVG so no image files ship.

They are simplified glyphs in each service's usual colours, enough to tell the channels apart at a glance (Teams follows its
own logo closely); drawn here rather than shipped as image files, so every system shows the same thing.
"""
from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# 64x64 canvases
SVG = {
    # a blurple tile with the white face-and-ears mark
    "discord": '<rect width="64" height="64" rx="14" fill="#5865F2"/>'
               '<path d="M16 22 Q22 17 29 16 L31 20 Q32 20 33 20 L35 16 Q42 17 48 22 Q53 31 52 44 Q46 49 40 50 L37 46 '
               'Q32 47 27 46 L24 50 Q18 49 12 44 Q11 31 16 22Z" fill="#fff"/>'
               '<ellipse cx="25" cy="35" rx="4" ry="4.8" fill="#5865F2"/><ellipse cx="39" cy="35" rx="4" ry="4.8" fill="#5865F2"/>',
    # four coloured pills and their round ends, as a pinwheel
    "slack": '<rect x="25" y="6" width="10" height="24" rx="5" fill="#36C5F0"/><circle cx="14" cy="20" r="5.5" fill="#36C5F0"/>'
             '<rect x="34" y="25" width="24" height="10" rx="5" fill="#2EB67D"/><circle cx="44" cy="14" r="5.5" fill="#2EB67D"/>'
             '<rect x="29" y="34" width="10" height="24" rx="5" fill="#ECB22E"/><circle cx="50" cy="44" r="5.5" fill="#ECB22E"/>'
             '<rect x="6" y="29" width="24" height="10" rx="5" fill="#E01E5A"/><circle cx="20" cy="50" r="5.5" fill="#E01E5A"/>',
    # Microsoft Teams: the purple T tile in front of two people (the back one darker), in Teams' own colours
    "teams": '<circle cx="51" cy="15" r="6.5" fill="#5059C9"/>'
             '<path d="M42 25h16.5a3.5 3.5 0 0 1 3.5 3.5V43a10 10 0 0 1-10 10h0a10 10 0 0 1-10-10z" fill="#5059C9"/>'
             '<circle cx="34" cy="12.5" r="9" fill="#7B83EB"/>'
             '<path d="M20 24h28a3 3 0 0 1 3 3v17a15 15 0 0 1-15 15h0a15 15 0 0 1-15-15z" fill="#7B83EB"/>'
             '<rect x="3" y="16" width="32" height="32" rx="4" fill="#4B53BC"/>'
             '<path d="M10 23.5h18v5h-6.5V42h-5V28.5H10z" fill="#fff"/>',
    "email": '<rect x="5" y="13" width="54" height="38" rx="6" fill="#3B82F6"/>'
             '<path d="M8 19 L32 38 L56 19" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>',
    # three joined nodes
    "webhook": '<path d="M32 14 L16 46 M32 14 L48 46 M16 46 L48 46" fill="none" stroke="#64748B" stroke-width="5" stroke-linecap="round"/>'
               '<circle cx="32" cy="14" r="9" fill="#F59E0B"/><circle cx="16" cy="46" r="9" fill="#10B981"/><circle cx="48" cy="46" r="9" fill="#3B82F6"/>',
    # a green tile with a terminal prompt
    "ntfy": '<rect width="64" height="64" rx="14" fill="#338574"/>'
            '<path d="M17 21 L31 32 L17 43" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>'
            '<path d="M35 45 H49" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round"/>',
    # the four panes
    "desktop": '<rect x="6" y="6" width="25" height="25" rx="2" fill="#0078D4"/><rect x="33" y="6" width="25" height="25" rx="2" fill="#0078D4"/>'
               '<rect x="6" y="33" width="25" height="25" rx="2" fill="#0078D4"/><rect x="33" y="33" width="25" height="25" rx="2" fill="#0078D4"/>',
    # ---- where passwords are kept (Settings > Security > Store passwords in)
    # Toner's own vault: a padlock on a slate tile
    "toner": '<rect width="64" height="64" rx="14" fill="#334155"/>'
             '<path d="M22 29 V22 A10 10 0 0 1 42 22 V29" fill="none" stroke="#fff" stroke-width="5"/>'
             '<rect x="16" y="28" width="32" height="24" rx="4" fill="#fff"/><circle cx="32" cy="39" r="4" fill="#334155"/>',
    # a blue tile with a white shield, its right half lighter
    "bitwarden": '<rect width="64" height="64" rx="14" fill="#175DDC"/>'
                 '<path d="M16 12 H48 V34 Q48 46 32 54 Q16 46 16 34 Z" fill="#fff"/>'
                 '<path d="M32 17 H43 V34 Q43 43 32 48 Z" fill="#175DDC" opacity=".35"/>',
    # the same shield on a dark tile, with a cog for "your own server"
    "vaultwarden": '<rect width="64" height="64" rx="14" fill="#1F2937"/>'
                   '<path d="M16 12 H48 V34 Q48 46 32 54 Q16 46 16 34 Z" fill="#fff"/>'
                   '<circle cx="32" cy="31" r="9" fill="none" stroke="#1F2937" stroke-width="4" stroke-dasharray="4 3"/>'
                   '<circle cx="32" cy="31" r="3.5" fill="#1F2937"/>',
    # a yellow tile with a black K
    "keeper": '<rect width="64" height="64" rx="14" fill="#FFC700"/>'
              '<path d="M20 14 H28 V29 L39 14 H48 L35 32 L48 50 H39 L28 35 V50 H20 Z" fill="#111"/>',
    # a blue disc with a white keyhole
    "onepassword": '<circle cx="32" cy="32" r="29" fill="#0572EC"/><circle cx="32" cy="32" r="21" fill="none" stroke="#fff" stroke-width="4"/>'
                   '<rect x="28.5" y="19" width="7" height="26" rx="3.5" fill="#fff"/>',
}
_cache = {}

# ---- the Assistant's providers (Settings > AI). BRAND_SVG holds each company's own mark as published on its brand page, the whole
# SVG file unmodified, one for light surfaces and one for dark (see core/assistant). Were a mark missing, a plain tile would stand in.
# OpenAI: the Blossom from https://openai.com/brand/ (openai-logos.zip, fetched 2026-10-25, used under OpenAI's Marks usage terms:
# unmodified, in its own colours, never more prominent than Toner's own mark). Its file keeps the clear space OpenAI prescribes.
OPENAI_BLOSSOM_BLACK = '<svg width="716" height="716" viewBox="0 0 716 716" fill="none" xmlns="http://www.w3.org/2000/svg">\n<path d="M508.749 317.399C516.777 287.314 508.991 253.884 485.389 230.282C461.788 206.681 428.36 198.895 398.273 206.923C376.231 184.928 343.39 174.956 311.148 183.596C278.906 192.234 255.45 217.292 247.36 247.361C217.291 255.451 192.233 278.91 183.595 311.149C174.957 343.391 184.927 376.232 206.924 398.274C198.896 428.359 206.683 461.789 230.284 485.391C253.885 508.992 287.313 516.779 317.401 508.75C339.442 530.745 372.286 540.717 404.525 532.079C436.767 523.441 460.223 498.384 468.313 468.315C498.383 460.224 523.44 436.766 532.078 404.526C540.716 372.285 530.747 339.443 508.749 317.402V317.399ZM470.899 244.776C486.892 260.77 493.488 282.601 490.687 303.412L415.577 260.046C412.411 258.218 408.509 258.218 405.345 260.046L317.401 310.82V277.526C317.401 275.191 318.652 273.005 320.676 271.837L387.644 233.174C414.178 218.353 448.346 222.223 470.901 244.776H470.899ZM357.837 311.144L398.275 334.491V381.185L357.837 404.532L317.398 381.185V334.491L357.837 311.144ZM264.776 269.693C265.207 239.305 285.644 211.649 316.453 203.393C338.3 197.54 360.505 202.744 377.127 215.573L302.014 258.937C298.848 260.764 296.898 264.144 296.898 267.798V369.346L268.065 352.699C266.043 351.531 264.776 349.353 264.776 347.017V269.691V269.693ZM203.391 316.454C209.244 294.608 224.854 277.978 244.276 269.999V356.73C244.276 360.384 246.226 363.763 249.392 365.591L337.337 416.365L308.503 433.013C306.481 434.181 303.961 434.188 301.939 433.02L234.971 394.357C208.868 378.789 195.138 347.261 203.391 316.454ZM244.775 470.9C228.781 454.906 222.186 433.075 224.986 412.264L300.096 455.63C303.263 457.457 307.164 457.457 310.328 455.63L398.273 404.856V438.149C398.273 440.485 397.022 442.671 394.997 443.839L328.029 482.502C301.495 497.322 267.327 493.452 244.772 470.9H244.775ZM450.897 445.982C450.466 476.371 430.029 504.027 399.22 512.283C377.373 518.136 355.168 512.932 338.547 500.102L413.659 456.738C416.826 454.911 418.775 451.532 418.775 447.877V346.329L447.609 362.977C449.631 364.145 450.897 366.323 450.897 368.659V445.985V445.982ZM512.282 399.221C506.429 421.068 490.819 437.697 471.397 445.676V358.946C471.397 355.292 469.448 351.912 466.281 350.085L378.336 299.311L407.17 282.663C409.192 281.495 411.712 281.487 413.734 282.655L480.702 321.318C506.805 336.887 520.536 368.415 512.282 399.221Z" fill="black"/>\n</svg>\n'
OPENAI_BLOSSOM_WHITE = '<svg width="716" height="716" viewBox="0 0 716 716" fill="none" xmlns="http://www.w3.org/2000/svg">\n<path d="M508.749 317.399C516.777 287.314 508.991 253.884 485.389 230.282C461.788 206.681 428.36 198.895 398.273 206.923C376.231 184.928 343.39 174.956 311.148 183.596C278.906 192.234 255.45 217.292 247.36 247.361C217.291 255.451 192.233 278.91 183.595 311.149C174.957 343.391 184.927 376.232 206.924 398.274C198.896 428.359 206.683 461.789 230.284 485.391C253.885 508.992 287.313 516.779 317.401 508.75C339.442 530.745 372.286 540.717 404.525 532.079C436.767 523.441 460.223 498.384 468.313 468.315C498.383 460.224 523.44 436.766 532.078 404.526C540.716 372.285 530.747 339.443 508.749 317.402V317.399ZM470.899 244.776C486.892 260.77 493.488 282.601 490.687 303.412L415.577 260.046C412.411 258.218 408.509 258.218 405.345 260.046L317.401 310.82V277.526C317.401 275.191 318.652 273.005 320.676 271.837L387.644 233.174C414.178 218.353 448.346 222.223 470.901 244.776H470.899ZM357.837 311.144L398.275 334.491V381.185L357.837 404.532L317.398 381.185V334.491L357.837 311.144ZM264.776 269.693C265.207 239.305 285.644 211.649 316.453 203.393C338.3 197.54 360.505 202.744 377.127 215.573L302.014 258.937C298.848 260.764 296.898 264.144 296.898 267.798V369.346L268.065 352.699C266.043 351.531 264.776 349.353 264.776 347.017V269.691V269.693ZM203.391 316.454C209.244 294.608 224.854 277.978 244.276 269.999V356.73C244.276 360.384 246.226 363.763 249.392 365.591L337.337 416.365L308.503 433.013C306.481 434.181 303.961 434.188 301.939 433.02L234.971 394.357C208.868 378.789 195.138 347.261 203.391 316.454ZM244.775 470.9C228.781 454.906 222.186 433.075 224.986 412.264L300.096 455.63C303.263 457.457 307.164 457.457 310.328 455.63L398.273 404.856V438.149C398.273 440.485 397.022 442.671 394.997 443.839L328.029 482.502C301.495 497.322 267.327 493.452 244.772 470.9H244.775ZM450.897 445.982C450.466 476.371 430.029 504.027 399.22 512.283C377.373 518.136 355.168 512.932 338.547 500.102L413.659 456.738C416.826 454.911 418.775 451.532 418.775 447.877V346.329L447.609 362.977C449.631 364.145 450.897 366.323 450.897 368.659V445.985V445.982ZM512.282 399.221C506.429 421.068 490.819 437.697 471.397 445.676V358.946C471.397 355.292 469.448 351.912 466.281 350.085L378.336 299.311L407.17 282.663C409.192 281.495 411.712 281.487 413.734 282.655L480.702 321.318C506.805 336.887 520.536 368.415 512.282 399.221Z" fill="white"/>\n</svg>\n'
# Claude and Gemini: the icons from uxwing.com (claude-ai-icon.svg and google-gemini-icon.svg, fetched 2026-10-26; uxwing's licence:
# "All icons on this site can be used for personal, commercial, and client projects without attribution"), unmodified. Each has its
# own colours, so the same file serves light and dark surfaces.
CLAUDE_ICON = '<svg xmlns="http://www.w3.org/2000/svg" shape-rendering="geometricPrecision" text-rendering="geometricPrecision" image-rendering="optimizeQuality" fill-rule="evenodd" clip-rule="evenodd" viewBox="0 0 512 509.64"><path fill="#D77655" d="M115.612 0h280.775C459.974 0 512 52.026 512 115.612v278.415c0 63.587-52.026 115.612-115.613 115.612H115.612C52.026 509.639 0 457.614 0 394.027V115.612C0 52.026 52.026 0 115.612 0z"/><path fill="#FCF2EE" fill-rule="nonzero" d="M142.27 316.619l73.655-41.326 1.238-3.589-1.238-1.996-3.589-.001-12.31-.759-42.084-1.138-36.498-1.516-35.361-1.896-8.897-1.895-8.34-10.995.859-5.484 7.482-5.03 10.717.935 23.683 1.617 35.537 2.452 25.782 1.517 38.193 3.968h6.064l.86-2.451-2.073-1.517-1.618-1.517-36.776-24.922-39.81-26.338-20.852-15.166-11.273-7.683-5.687-7.204-2.451-15.721 10.237-11.273 13.75.935 3.513.936 13.928 10.716 29.749 23.027 38.848 28.612 5.687 4.727 2.275-1.617.278-1.138-2.553-4.271-21.13-38.193-22.546-38.848-10.035-16.101-2.654-9.655c-.935-3.968-1.617-7.304-1.617-11.374l11.652-15.823 6.445-2.073 15.545 2.073 6.547 5.687 9.655 22.092 15.646 34.78 24.265 47.291 7.103 14.028 3.791 12.992 1.416 3.968 2.449-.001v-2.275l1.997-26.641 3.69-32.707 3.589-42.084 1.239-11.854 5.863-14.206 11.652-7.683 9.099 4.348 7.482 10.716-1.036 6.926-4.449 28.915-8.72 45.294-5.687 30.331h3.313l3.792-3.791 15.342-20.372 25.782-32.227 11.374-12.789 13.27-14.129 8.517-6.724 16.1-.001 11.854 17.617-5.307 18.199-16.581 21.029-13.75 17.819-19.716 26.54-12.309 21.231 1.138 1.694 2.932-.278 44.536-9.479 24.062-4.347 28.714-4.928 12.992 6.066 1.416 6.167-5.106 12.613-30.71 7.583-36.018 7.204-53.636 12.689-.657.48.758.935 24.164 2.275 10.337.556h25.301l47.114 3.514 12.309 8.139 7.381 9.959-1.238 7.583-18.957 9.655-25.579-6.066-59.702-14.205-20.474-5.106-2.83-.001v1.694l17.061 16.682 31.266 28.233 39.152 36.397 1.997 8.999-5.03 7.102-5.307-.758-34.401-25.883-13.27-11.651-30.053-25.302-1.996-.001v2.654l6.926 10.136 36.574 54.975 1.895 16.859-2.653 5.485-9.479 3.311-10.414-1.895-21.408-30.054-22.092-33.844-17.819-30.331-2.173 1.238-10.515 113.261-4.929 5.788-11.374 4.348-9.478-7.204-5.03-11.652 5.03-23.027 6.066-30.052 4.928-23.886 4.449-29.674 2.654-9.858-.177-.657-2.173.278-22.37 30.71-34.021 45.977-26.919 28.815-6.445 2.553-11.173-5.789 1.037-10.337 6.243-9.2 37.257-47.392 22.47-29.371 14.508-16.961-.101-2.451h-.859l-98.954 64.251-17.618 2.275-7.583-7.103.936-11.652 3.589-3.791 29.749-20.474-.101.102.024.101z"/></svg>'
GEMINI_ICON = '<svg fill="none" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 65 65"><mask id="maskme" style="mask-type:alpha" maskUnits="userSpaceOnUse" x="0" y="0" width="65" height="65"><path d="M32.447 0c.68 0 1.273.465 1.439 1.125a38.904 38.904 0 001.999 5.905c2.152 5 5.105 9.376 8.854 13.125 3.751 3.75 8.126 6.703 13.125 8.855a38.98 38.98 0 005.906 1.999c.66.166 1.124.758 1.124 1.438 0 .68-.464 1.273-1.125 1.439a38.902 38.902 0 00-5.905 1.999c-5 2.152-9.375 5.105-13.125 8.854-3.749 3.751-6.702 8.126-8.854 13.125a38.973 38.973 0 00-2 5.906 1.485 1.485 0 01-1.438 1.124c-.68 0-1.272-.464-1.438-1.125a38.913 38.913 0 00-2-5.905c-2.151-5-5.103-9.375-8.854-13.125-3.75-3.749-8.125-6.702-13.125-8.854a38.973 38.973 0 00-5.905-2A1.485 1.485 0 010 32.448c0-.68.465-1.272 1.125-1.438a38.903 38.903 0 005.905-2c5-2.151 9.376-5.104 13.125-8.854 3.75-3.749 6.703-8.125 8.855-13.125a38.972 38.972 0 001.999-5.905A1.485 1.485 0 0132.447 0z" fill="#000"/><path d="M32.447 0c.68 0 1.273.465 1.439 1.125a38.904 38.904 0 001.999 5.905c2.152 5 5.105 9.376 8.854 13.125 3.751 3.75 8.126 6.703 13.125 8.855a38.98 38.98 0 005.906 1.999c.66.166 1.124.758 1.124 1.438 0 .68-.464 1.273-1.125 1.439a38.902 38.902 0 00-5.905 1.999c-5 2.152-9.375 5.105-13.125 8.854-3.749 3.751-6.702 8.126-8.854 13.125a38.973 38.973 0 00-2 5.906 1.485 1.485 0 01-1.438 1.124c-.68 0-1.272-.464-1.438-1.125a38.913 38.913 0 00-2-5.905c-2.151-5-5.103-9.375-8.854-13.125-3.75-3.749-8.125-6.702-13.125-8.854a38.973 38.973 0 00-5.905-2A1.485 1.485 0 010 32.448c0-.68.465-1.272 1.125-1.438a38.903 38.903 0 005.905-2c5-2.151 9.376-5.104 13.125-8.854 3.75-3.749 6.703-8.125 8.855-13.125a38.972 38.972 0 001.999-5.905A1.485 1.485 0 0132.447 0z" fill="url(#prefix__paint0_linear_2001_67)"/></mask><g mask="url(#maskme)"><g filter="url(#prefix__filter0_f_2001_67)"><path d="M-5.859 50.734c7.498 2.663 16.116-2.33 19.249-11.152 3.133-8.821-.406-18.131-7.904-20.794-7.498-2.663-16.116 2.33-19.25 11.151-3.132 8.822.407 18.132 7.905 20.795z" fill="#FFE432"/></g><g filter="url(#prefix__filter1_f_2001_67)"><path d="M27.433 21.649c10.3 0 18.651-8.535 18.651-19.062 0-10.528-8.35-19.062-18.651-19.062S8.78-7.94 8.78 2.587c0 10.527 8.35 19.062 18.652 19.062z" fill="#FC413D"/></g><g filter="url(#prefix__filter2_f_2001_67)"><path d="M20.184 82.608c10.753-.525 18.918-12.244 18.237-26.174-.68-13.93-9.95-24.797-20.703-24.271C6.965 32.689-1.2 44.407-.519 58.337c.681 13.93 9.95 24.797 20.703 24.271z" fill="#00B95C"/></g><g filter="url(#prefix__filter3_f_2001_67)"><path d="M20.184 82.608c10.753-.525 18.918-12.244 18.237-26.174-.68-13.93-9.95-24.797-20.703-24.271C6.965 32.689-1.2 44.407-.519 58.337c.681 13.93 9.95 24.797 20.703 24.271z" fill="#00B95C"/></g><g filter="url(#prefix__filter4_f_2001_67)"><path d="M30.954 74.181c9.014-5.485 11.427-17.976 5.389-27.9-6.038-9.925-18.241-13.524-27.256-8.04-9.015 5.486-11.428 17.977-5.39 27.902 6.04 9.924 18.242 13.523 27.257 8.038z" fill="#00B95C"/></g><g filter="url(#prefix__filter5_f_2001_67)"><path d="M67.391 42.993c10.132 0 18.346-7.91 18.346-17.666 0-9.757-8.214-17.667-18.346-17.667s-18.346 7.91-18.346 17.667c0 9.757 8.214 17.666 18.346 17.666z" fill="#3186FF"/></g><g filter="url(#prefix__filter6_f_2001_67)"><path d="M-13.065 40.944c9.33 7.094 22.959 4.869 30.442-4.972 7.483-9.84 5.987-23.569-3.343-30.663C4.704-1.786-8.924.439-16.408 10.28c-7.483 9.84-5.986 23.57 3.343 30.664z" fill="#FBBC04"/></g><g filter="url(#prefix__filter7_f_2001_67)"><path d="M34.74 51.43c11.135 7.656 25.896 5.524 32.968-4.764 7.073-10.287 3.779-24.832-7.357-32.488C49.215 6.52 34.455 8.654 27.382 18.94c-7.072 10.288-3.779 24.833 7.357 32.49z" fill="#3186FF"/></g><g filter="url(#prefix__filter8_f_2001_67)"><path d="M54.984-2.336c2.833 3.852-.808 11.34-8.131 16.727-7.324 5.387-15.557 6.631-18.39 2.78-2.833-3.853.807-11.342 8.13-16.728 7.324-5.387 15.558-6.631 18.39-2.78z" fill="#749BFF"/></g><g filter="url(#prefix__filter9_f_2001_67)"><path d="M31.727 16.104C43.053 5.598 46.94-8.626 40.41-15.666c-6.53-7.04-21.006-4.232-32.332 6.274s-15.214 24.73-8.683 31.77c6.53 7.04 21.006 4.232 32.332-6.274z" fill="#FC413D"/></g><g filter="url(#prefix__filter10_f_2001_67)"><path d="M8.51 53.838c6.732 4.818 14.46 5.55 17.262 1.636 2.802-3.915-.384-10.994-7.116-15.812-6.731-4.818-14.46-5.55-17.261-1.636-2.802 3.915.383 10.994 7.115 15.812z" fill="#FFEE48"/></g></g><defs><filter id="prefix__filter0_f_2001_67" x="-19.824" y="13.152" width="39.274" height="43.217" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="2.46" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter1_f_2001_67" x="-15.001" y="-40.257" width="84.868" height="85.688" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="11.891" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter2_f_2001_67" x="-20.776" y="11.927" width="79.454" height="90.916" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="10.109" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter3_f_2001_67" x="-20.776" y="11.927" width="79.454" height="90.916" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="10.109" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter4_f_2001_67" x="-19.845" y="15.459" width="79.731" height="81.505" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="10.109" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter5_f_2001_67" x="29.832" y="-11.552" width="75.117" height="73.758" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="9.606" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter6_f_2001_67" x="-38.583" y="-16.253" width="78.135" height="78.758" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="8.706" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter7_f_2001_67" x="8.107" y="-5.966" width="78.877" height="77.539" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="7.775" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter8_f_2001_67" x="13.587" y="-18.488" width="56.272" height="51.81" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="6.957" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter9_f_2001_67" x="-15.526" y="-31.297" width="70.856" height="69.306" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="5.876" result="effect1_foregroundBlur_2001_67"/></filter><filter id="prefix__filter10_f_2001_67" x="-14.168" y="20.964" width="55.501" height="51.571" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur stdDeviation="7.273" result="effect1_foregroundBlur_2001_67"/></filter><linearGradient id="prefix__paint0_linear_2001_67" x1="18.447" y1="43.42" x2="52.153" y2="15.004" gradientUnits="userSpaceOnUse"><stop stop-color="#4893FC"/><stop offset=".27" stop-color="#4893FC"/><stop offset=".777" stop-color="#969DFF"/><stop offset="1" stop-color="#BD99FE"/></linearGradient></defs></svg>'
BRAND_SVG = {"claude": {"light": CLAUDE_ICON, "dark": CLAUDE_ICON},
             "openai": {"light": OPENAI_BLOSSOM_BLACK, "dark": OPENAI_BLOSSOM_WHITE},
             "gemini": {"light": GEMINI_ICON, "dark": GEMINI_ICON}}
PROVIDER_FALLBACK = {
    "claude": '<rect width="64" height="64" rx="14" fill="#D97757"/><path d="M20 16h8l12 32h-8z M36 16h8L32 48h-8z" fill="#fff"/>',
    "openai": '<rect width="64" height="64" rx="14" fill="#000"/><circle cx="32" cy="32" r="15" fill="none" stroke="#fff" stroke-width="5"/>',
    "gemini": '<rect width="64" height="64" rx="14" fill="#1F6FEB"/><path d="M32 12 Q34 30 52 32 Q34 34 32 52 Q30 34 12 32 Q30 30 32 12Z" fill="#fff"/>',
}


def _pixmap_doc(svg, size):
    """Render a whole SVG document (its own viewBox) into a square of `size` pixels, keeping its proportions."""
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    r = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    box = r.viewBoxF()
    w, h = (box.width(), box.height()) if box.width() > 0 and box.height() > 0 else (r.defaultSize().width() or 1, r.defaultSize().height() or 1)
    scale = size / max(w, h)
    dw, dh = w * scale, h * scale
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    r.render(p, QRectF((size - dw) / 2, (size - dh) / 2, dw, dh))
    p.end()
    return QPixmap.fromImage(img)


def on_dark():
    """True when the window's surfaces are dark (the white marks are for those)."""
    from PySide6.QtGui import QColor
    from ui import theme
    t = theme.current() or {}
    return QColor(t.get("surface", "#ffffff")).lightness() < 128


def has_brand_mark(provider):
    return provider in BRAND_SVG


def mark_size(provider, button):
    """How big a provider's mark is drawn inside a round button of `button` pixels: OpenAI's file carries its own clear space, so it
    takes the whole button; the uxwing tiles fill their canvas, so they sit inside it; a placeholder stays small."""
    if provider == "openai":
        return (button, button)
    if provider in BRAND_SVG:
        return (button - 16, button - 16)
    return (24, 24)


def provider_icon(provider):
    """The mark of an Assistant provider: 'claude', 'openai' or 'gemini'. A company's own mark comes in a light and a dark version;
    the theme picks."""
    variant = "dark" if on_dark() else "light"
    key = f"provider:{provider}:{variant}"
    if key not in _cache:
        ic = QIcon()
        for size in (16, 24, 32, 48, 64):
            if provider in BRAND_SVG:
                ic.addPixmap(_pixmap_doc(BRAND_SVG[provider][variant], size))
            else:
                svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">{PROVIDER_FALLBACK.get(provider, PROVIDER_FALLBACK["claude"])}</svg>'
                ic.addPixmap(_pixmap_doc(svg, size))
        _cache[key] = ic
    return _cache[key]


def _pixmap(name, size):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">{SVG[name]}</svg>'
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    QSvgRenderer(QByteArray(svg.encode())).render(p, QRectF(0, 0, size, size))
    p.end()
    return QPixmap.fromImage(img)


def vault_icon(kind):
    """The mark for a place passwords are kept: 'toner', 'bitwarden', 'vaultwarden', 'keeper', 'onepassword'."""
    return channel_icon(kind if kind in SVG else "toner")


def channel_icon(ctype):
    """The mark for a notification channel type ('discord', 'slack', ...). An unknown type gets the generic webhook mark."""
    name = ctype if ctype in SVG else "webhook"
    if name not in _cache:
        ic = QIcon()
        for size in (16, 24, 32, 48, 64):               # sharp at any display scale
            ic.addPixmap(_pixmap(name, size))
        _cache[name] = ic
    return _cache[name]
