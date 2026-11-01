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


# ---- the device vendors (the device window and the Inventory's details pane). Each maker's mark is drawn in white on a rounded tile in
# the maker's colour; a maker without a mark here gets two letters on the tile instead. The marks are Simple Icons' (simpleicons.org,
# github.com/simple-icons/simple-icons, fetched 2026-11-01 from the icons/ folder of the develop branch; CC0 1.0: no attribution needed,
# the marks themselves stay their owners' trademarks), each file a <title> and one <path> in a 24 x 24 box, reproduced here as
# (title, path). Simple Icons has no Arista, HPE, Windows or Meraki mark, so those four keep their letters.
VENDOR_PATHS = {
    "cisco": ("Cisco", "M16.331 18.171V17.06l-.022.01c-.25.121-.522.19-.801.203a1.186 1.186 0 01-.806-.237 1.038 1.038 0 01-.352-.498 1.21 1.21 0 01-.023-.667c.052-.225.178-.426.357-.569.16-.134.355-.218.562-.242a1.85 1.85 0 011.061.198l.024.013v-1.117l-.051-.014a2.862 2.862 0 00-1.011-.132 2.34 2.34 0 00-.903.206c-.287.132-.54.327-.739.571a2.221 2.221 0 00-.04 2.705c.295.378.709.645 1.175.756.491.12 1.006.102 1.487-.052l.082-.023M5.336 18.171V17.06l-.022.01c-.25.121-.522.19-.801.203a1.183 1.183 0 01-.806-.237 1.03 1.03 0 01-.351-.498 1.202 1.202 0 01-.024-.667c.052-.225.177-.426.357-.569.16-.134.355-.218.562-.242a1.85 1.85 0 011.061.198l.024.013v-1.117l-.051-.014a2.862 2.862 0 00-1.011-.132 2.344 2.344 0 00-.903.206 2.08 2.08 0 00-.74.571 2.224 2.224 0 00-.041 2.705 2.11 2.11 0 001.176.756c.491.12 1.005.102 1.487-.052l.083-.023M9.26 17.249l-.004.957.07.012c.22.041.441.069.664.085.195.019.391.022.587.012.187-.014.372-.049.551-.104.21-.06.405-.163.571-.305a1.16 1.16 0 00.333-.478 1.31 1.31 0 00-.007-.96 1.068 1.068 0 00-.298-.414 1.261 1.261 0 00-.438-.255l-.722-.268a.388.388 0 01-.197-.188.245.245 0 01.008-.219.382.382 0 01.154-.142.798.798 0 01.257-.074c.153-.022.308-.021.46.005.18.02.358.051.533.096l.038.008v-.883l-.069-.015a4.749 4.749 0 00-.543-.097 2.844 2.844 0 00-.714-.003c-.3.027-.585.143-.821.33-.16.126-.281.293-.351.484-.104.29-.105.608 0 .899.054.145.14.274.252.381.097.093.207.173.327.236.157.084.324.149.497.195.057.017.114.035.17.054l.085.031.024.01c.084.03.162.078.226.14.045.042.08.094.101.151a.325.325 0 01.001.161.339.339 0 01-.166.198.856.856 0 01-.275.086 2.032 2.032 0 01-.427.021 5.208 5.208 0 01-.557-.074 9.195 9.195 0 01-.287-.067l-.033-.006zm-2.475.995h1.05v-4.167h-1.05v4.167zm12.162-2.936a1.095 1.095 0 011.541.158 1.094 1.094 0 01-.157 1.541l-.017.014a1.096 1.096 0 01-1.367-1.713m-1.525.854a2.193 2.193 0 002.666 2.107 2.139 2.139 0 00.701-3.937 2.207 2.207 0 00-3.367 1.83M22.961 10.728a.52.52 0 001.039 0V9.573a.52.52 0 00-1.039 0v1.155M20.117 10.728a.522.522 0 001.041 0V8.139a.521.521 0 00-1.04 0v2.589M17.231 11.771a.521.521 0 001.039 0V6.17a.52.52 0 00-1.039 0v5.601M14.393 10.728a.521.521 0 001.04 0V8.139a.52.52 0 00-1.039 0v2.589M11.494 10.728a.522.522 0 001.039 0V9.573a.52.52 0 00-1.039 0v1.155M8.624 10.728a.52.52 0 001.039 0V8.139a.52.52 0 00-1.039 0v2.589M5.737 11.771a.52.52 0 001.039 0V6.17a.52.52 0 00-1.039 0v5.601M2.876 10.728a.522.522 0 001.04 0V8.139a.52.52 0 00-1.039 0v2.589M0 10.728a.521.521 0 001.039 0V9.573a.52.52 0 00-1.039 0v1.155"),
    "fortinet": ("Fortinet", "M0 9.785h6.788v4.454H0zm8.666-6.33h6.668v4.453H8.666zm0 12.637h6.668v4.454H8.666zm8.522-6.307H24v4.454h-6.812zM2.792 3.455C1.372 3.814.265 5.404 0 7.425v.506h6.788V3.454zM0 16.091v.554c.24 1.926 1.276 3.466 2.624 3.9h4.188v-4.454zm24-8.184v-.506c-.265-1.998-1.372-3.587-2.792-3.972h-4.02v4.454H24zM21.376 20.57c1.324-.458 2.36-1.974 2.624-3.9v-.554h-6.812v4.454Z"),
    "paloalto": ("Palo Alto Networks", "m10.278 15.443 1.705 1.705-3.426 3.426-3.427-3.426 8.592-8.591-1.705-1.705 3.426-3.426 3.427 3.426-8.592 8.591zM0 12.017l3.426 3.426 8.591-8.59-3.426-3.427L0 12.017zm11.983 5.13 3.426 3.427L24 11.983l-3.426-3.426-8.591 8.59z"),
    "juniper": ("Juniper Networks", "M23.0864 13.1643c.0456 0 .0717-.0132.0717-.062 0-.0482-.0254-.0593-.0731-.0593h-.1023v.1213zm-.1037.0417v.1285h-.0445v-.334h.1487c.0846 0 .1172.0347.1172.1006 0 .054-.0229.0912-.0806.102l.0755.1314h-.0484l-.0746-.1285zm.0746-.2918a.2535.2535 0 0 0-.2533.2531c0 .1395.1136.2532.2533.2532a.2535.2535 0 0 0 .253-.2532.2534.2534 0 0 0-.253-.2531zm-.291.2531a.2912.2912 0 0 1 .291-.2908.291.291 0 0 1 .2905.2908.291.291 0 0 1-.2905.2907.2912.2912 0 0 1-.291-.2907zm-20.7445-.6602V8.8304h-.4212v3.6767c0 .8506.0337 1.5332-1.4404 1.5332A4.029 4.029 0 0 1 0 14.0369v.397a6.215 6.215 0 0 0 .1602.0022c1.7858 0 1.8616-.8002 1.8616-1.929zm15.5404-1.6972h3.1334c-.042-.918-.1011-1.7014-1.4404-1.7014-1.2887 0-1.6425.6992-1.693 1.7014zm1.7016-2.0889c1.794 0 1.853 1.2045 1.8447 2.4764h-3.5548c.0085 1.1204.2863 1.9544 1.7436 1.9544.775 0 1.1288-.2107 1.5079-.4886l.2357.3116c-.421.3117-.918.556-1.7436.556-1.8194 0-2.1565-1.053-2.1565-2.4091 0-1.356.3877-2.4007 2.123-2.4007zm-4.1484 2.7055c.7439 0 1.1135-.3625 1.1135-1.0949 0-.7322-.3988-1.0798-1.132-1.0798h-1.7285v2.1747zM15.109 8.839c1.0678 0 1.5519.5307 1.5519 1.474 0 .9497-.478 1.527-1.5578 1.527h-1.7348v1.5981h-.4124V8.839zm-2.9253 0v4.5991h-.4122V8.839zm-1.1939 4.5991h-.4296v-2.8134c0-.8086.0084-1.491-1.474-1.491-1.4743 0-1.4405.6824-1.4405 1.5331v2.7713h-.4212v-2.7713c0-1.1288.076-1.9289 1.8616-1.9289 1.7943 0 1.9037.8001 1.9037 1.8952zM2.7466 8.8304h.4297v2.8134c0 .8088-.0084 1.491 1.474 1.491 1.4742 0 1.4405-.6822 1.4405-1.533V8.8303h.4212v2.7713c0 1.1289-.0759 1.929-1.8616 1.929-1.7943 0-1.9038-.8001-1.9038-1.8952zm18.9675 1.8364v2.7713h.421v-2.7713c0-.8507-.0336-1.533 1.4407-1.533.1579 0 .298.0083.4242.023v-.4012a4.8535 4.8535 0 0 0-.4242-.0177c-1.7859 0-1.8617.8001-1.8617 1.929zm-.4315 4.3602c.1525.096.3017.1286.4542.1286.2624 0 .3789-.0737.3789-.2486 0-.18-.1508-.2057-.3789-.2468-.2743-.048-.4594-.0944-.4594-.3514 0-.2453.1577-.3413.4594-.3413.199 0 .3412.0447.4423.1132l-.072.1097c-.0908-.06-.2263-.0995-.3703-.0995-.228 0-.3257.0636-.3257.2144 0 .1612.132.192.3584.233.2776.0499.4782.091.4782.3635 0 .2521-.1612.3737-.5074.3737-.192 0-.3652-.0393-.5263-.1456zm-.7886-.4423l-.2538.2777v.396h-.132v-1.2703h.132v.7012l.643-.7012h.156l-.456.4989.5176.7715h-.1525l-.4543-.6738m-1.1006.0326c.18 0 .2914-.0549.2914-.2555 0-.1971-.108-.2485-.2965-.2485h-.4132v.504zm-.0377.1234h-.3806v.5178h-.132V13.988h.5486c.2948 0 .4286.1183.4286.3703 0 .2194-.1046.348-.3258.377l.3068.523h-.1439l-.3017-.5177m-.924-.1166c0-.3429-.1594-.528-.5058-.528-.3446 0-.5023.1851-.5023.528 0 .3446.1577.5298.5023.5298.3464 0 .5058-.1852.5058-.5298zm-.5058-.6566c.408 0 .6412.2024.6412.655 0 .4542-.2332.6565-.6412.6565-.4063 0-.6377-.2023-.6377-.6566 0-.4525.2314-.6549.6377-.6549zm-2.3571.0206l.3342 1.0508.3412-1.0508h.1166l.3394 1.0508.336-1.0508h.1303l-.408 1.2789h-.1165l-.343-1.0577-.341 1.0577h-.1183l-.4098-1.2789zm-1.392.1286v-.1286h1.0886v.1286h-.4766v1.1418h-.1355v-1.1418zm-.204-.1286v.1286h-.7046v.42h.6874v.127h-.6874v.4713h.7114v.1235h-.8468V13.988zm-2.0539 0l.7596 1.0475V13.988h.1303v1.2704h-.1235l-.7835-1.0784v1.0784h-.1303V13.988Z"),
    "mikrotik": ("MikroTik", "M23.041 6.188a1.404 1.404 0 0 0-.218-.36c-.24-.296-.634-.586-1.14-.864l-4.052-2.22L13.576.519C13.074.243 12.61.065 12.22.013A1.772 1.772 0 0 0 12 0c-.432 0-.974.192-1.576.52L6.37 2.74 2.317 4.96c-.504.279-.9.569-1.14.867a1.59 1.59 0 0 0-.122.17 1.654 1.654 0 0 0-.096.19c-.15.348-.22.816-.22 1.368v8.887c0 .66.1 1.2.316 1.558.216.356.66.706 1.262 1.036l4.054 2.22 4.053 2.223c.504.276.966.456 1.36.506.145.02.291.02.436 0 .39-.05.852-.228 1.356-.506l8.107-4.443c.6-.33 1.046-.68 1.262-1.036.036-.06.068-.123.096-.188.15-.348.22-.818.22-1.37V7.556c0-.552-.07-1.02-.22-1.368zM7.233 16.618c0 .2-.218.33-.396.233l-1.45-.796a1.066 1.066 0 0 1-.552-.934v-4.296c0-.2.216-.33.394-.235l1.728.947a.53.53 0 0 1 .276.468v4.612zm11.934-1.497c0 .39-.213.748-.554.936l-1.45.794a.266.266 0 0 1-.394-.234v-5.692c0-.2-.217-.33-.395-.232l-2.62 1.434c-.34.187-.552.545-.552.934v5.646a.532.532 0 0 1-.278.468l-.41.224c-.32.176-.707.176-1.026 0l-.408-.224a.532.532 0 0 1-.278-.468v-5.646c0-.389-.212-.747-.552-.934L4.835 9.16v-.28c0-.388.212-.746.552-.934l.6-.328a1.064 1.064 0 0 1 1.022 0l4.48 2.452c.318.176.704.176 1.021 0l2.07-1.134a.266.266 0 0 0 0-.468L9.932 5.922a.266.266 0 0 1 0-.468l1.556-.852c.32-.176.707-.176 1.026 0l6.1 3.34c.342.188.554.547.553.936v6.243z"),
    "unifi": ("Ubiquiti", "M23.1627 0h-1.4882v1.4882h1.4882zm-5.2072 10.4226V7.4409l.0007.001h2.9755v2.9762h2.9756v.9433c0 1.0906-.0927 2.3827-.306 3.3973-.1194.5672-.3004 1.1308-.5127 1.672-.2175.5537-.468 1.0841-.7408 1.5595a11.6795 11.6795 0 0 1-1.2456 1.7762l-.0253.0294-.0417.0488c-.1148.1347-.2283.2679-.3531.398a11.7612 11.7612 0 0 1-.4494.4492c-1.9046 1.8343-4.3861 2.98-6.9808 3.243-.3122.032-.939.0652-1.2519.0652-.3139-.001-.9397-.0331-1.252-.0651-2.5946-.263-5.0761-1.4097-6.9806-3.243a11.75 11.75 0 0 1-.4495-.4494c-.131-.1356-.249-.2748-.3683-.4154l-.0006-.0004-.0512-.0603a11.6576 11.6576 0 0 1-1.2456-1.7762c-.2727-.4763-.5233-1.0058-.7408-1.5595-.2123-.5414-.3933-1.1048-.5128-1.6718C.1854 13.743.0927 12.452.0927 11.3616V.1864h5.9518v10.2362s0 .7847.0099 1.0415l.0022.0599v.0004c.0127.332.0247.6575.0594.9812.098.919.3014 1.7913.7203 2.5288.1213.213.2443.42.3915.616.8953 1.1939 2.2577 2.0901 3.9573 2.3398.2022.0294.6108.0552.8149.0552.204 0 .6125-.0258.8149-.0552 1.6996-.2497 3.062-1.146 3.9573-2.3398.148-.196.2701-.403.3914-.616.419-.7375.6224-1.6095.7204-2.5288.0346-.3243.047-.6503.0594-.9831l.0022-.0584c.0099-.2568.0099-1.0415.0099-1.0415zm.7427-8.19h2.2326v2.2319h2.9764v2.9764h-2.9764V4.4654h-2.2326V2.2328Z"),
    "proxmox": ("Proxmox", "M4.928 1.825c-1.09.553-1.09.64-.07 1.78 5.655 6.295 7.004 7.782 7.107 7.782.139.017 7.971-8.542 8.058-8.801.034-.07-.208-.312-.519-.536-.415-.312-.864-.433-1.712-.467-1.59-.104-2.144.242-4.115 2.455-.899 1.003-1.66 1.833-1.66 1.833-.017 0-.76-.813-1.642-1.798S8.473 2.1 8.127 1.91c-.796-.45-2.421-.484-3.2-.086zM1.297 4.367C.45 4.695 0 5.007 0 5.248c0 .121 1.331 1.678 2.94 3.459 1.625 1.78 2.939 3.268 2.939 3.302 0 .035-1.331 1.522-2.94 3.303C1.314 17.11.017 18.683.035 18.822c.086.467 1.504 1.055 2.541 1.055 1.678-.018 2.058-.312 5.603-4.202 1.78-1.954 3.233-3.614 3.233-3.666 0-.069-1.435-1.694-3.199-3.63-2.3-2.508-3.423-3.632-3.96-3.874-.812-.398-2.126-.467-2.956-.138zm18.467.12c-.502.26-1.764 1.505-3.943 3.891-1.763 1.937-3.199 3.562-3.199 3.631 0 .07 1.453 1.712 3.234 3.666 3.544 3.89 3.925 4.184 5.602 4.202 1.038 0 2.455-.588 2.542-1.055.017-.156-1.28-1.712-2.905-3.493-1.608-1.78-2.94-3.285-2.94-3.32 0-.034 1.332-1.539 2.94-3.32C22.72 6.91 24.017 5.352 24 5.214c-.087-.45-1.366-.968-2.473-1.038-.795-.034-1.21.035-1.763.312zM7.954 16.973c-2.144 2.369-3.908 4.374-3.943 4.46-.034.07.208.312.52.537.414.311.864.432 1.711.467 1.574.103 2.161-.26 4.15-2.508.864-.968 1.608-1.78 1.625-1.78s.761.812 1.643 1.798c2.023 2.248 2.559 2.576 4.132 2.49.848-.035 1.297-.156 1.712-.467.311-.225.553-.467.519-.536-.087-.26-7.92-8.819-8.058-8.801-.069 0-1.867 1.954-4.011 4.34z"),
    "truenas": ("TrueNAS", "M24 10.049v5.114l-10.949 6.324v-5.114L24 10.049zm-24 0v5.114l10.956 6.324v-5.114L0 10.049zm12.004-.605l-4.433 2.559 4.433 2.559 4.429-2.559-4.429-2.559zm10.952-1.207l-9.905-5.723v5.118l5.473 3.164 4.432-2.559zm-12-.605V2.513L1.044 8.236l4.432 2.555 5.48-3.159z"),
    "opnsense": ("OPNsense", "M5.25 0v5.25h13.5v13.5H24V7.5L16.5 0Zm13.5 18.75H5.25V5.25H0V16.5L7.5 24h11.25Z"),
}
VENDOR_TILES = {"cisco": ("#049FD9", "Ci"), "fortinet": ("#EE3124", "Ft"), "unifi": ("#0559C9", "Ub"), "proxmox": ("#E57000", "Px"),
                "truenas": ("#0095D5", "TN"), "opnsense": ("#D94F00", "OP"), "juniper": ("#84B135", "Jn"), "arista": ("#2B6FB6", "Ar"),
                "hpe": ("#01A982", "HP"), "mikrotik": ("#293239", "MT"), "paloalto": ("#FA582D", "PA"), "snmp": ("#6B7280", "SN"),
                "meraki": ("#67B346", "Mk"), "cloud": ("#0EA5E9", "Cl"), "windows": ("#0078D4", "Wn"), "wifi": ("#0EA5E9", "Wi")}


def vendor_tile_svg(vendor):
    """The maker's mark in white on a rounded tile in its colour, or, for a maker without a mark, two letters on the tile (grey '?' for
    a device without a vendor)."""
    colour, letters = VENDOR_TILES.get(vendor, ("#78838A", "?"))
    tile = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="{colour}"/>'
    if vendor in VENDOR_PATHS:
        _title, d = VENDOR_PATHS[vendor]
        return tile + f'<g transform="translate(14 14) scale(1.5)"><path fill="#ffffff" d="{d}"/></g></svg>'
    return tile + f'<text x="32" y="41" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-weight="700" font-size="26" fill="#ffffff">{letters}</text></svg>'


# ---- the user's own vendor icons: PNG files named after the vendor in a folder of their choosing (Settings > Appearance; by default
# Documents\Vendor Icons when it exists). A file there comes before the marks above. Names are matched loosely (case, spaces and
# punctuation ignored, a few aliases, and a near miss such as PRXMOX for Proxmox), so files can be dropped in without renaming.
VENDOR_FILE_NAMES = {
    "cisco": ("cisco", "ciscosystems"), "fortinet": ("fortinet", "fortigate"), "unifi": ("unifi", "ubiquiti", "ubnt"),
    "proxmox": ("proxmox", "proxmoxve"), "truenas": ("truenas", "ixsystems"), "opnsense": ("opnsense",), "juniper": ("juniper", "junipernetworks"),
    "arista": ("arista", "aristanetworks"), "hpe": ("hpe", "hp", "hpearuba", "aruba", "arubanetworks", "hewlettpackardenterprise"),
    "mikrotik": ("mikrotik",), "paloalto": ("paloalto", "paloaltonetworks", "panos"), "snmp": ("snmp",), "meraki": ("meraki", "ciscomeraki"),
    "cloud": ("cloud", "cloudstatus"), "windows": ("windows", "microsoft", "microsoftwindows"), "wifi": ("wifi", "wireless"),
}
ICON_FILE_TYPES = (".png", ".jpg", ".jpeg", ".bmp", ".webp")


def _norm(s):
    import re
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def icons_folder():
    """Where the user's vendor icons are: the Appearance setting, else Documents\\Vendor Icons when that exists, else ''."""
    import os
    try:
        from core import db
        chosen = str(db.get_setting("vendor_icons_folder") or "").strip()
    except Exception:
        chosen = ""
    if chosen:
        return chosen
    default = os.path.join(os.path.expanduser("~"), "Documents", "Vendor Icons")
    return default if os.path.isdir(default) else ""


def vendor_file(fam, folder=None):
    """The user's icon file for a vendor family, or None: an exact name first (CISCO.png, Palo Alto.png), then an alias, then a near miss."""
    import difflib
    import os
    folder = icons_folder() if folder is None else folder
    if not folder or not os.path.isdir(folder):
        return None
    try:
        files = {_norm(os.path.splitext(f)[0]): os.path.join(folder, f) for f in sorted(os.listdir(folder)) if f.lower().endswith(ICON_FILE_TYPES)}
    except OSError:
        return None
    names = tuple(VENDOR_FILE_NAMES.get(fam, ())) or ((fam,) if fam else ())
    for n in names:
        if n in files:
            return files[n]
    near = difflib.get_close_matches(names[0], list(files), n=1, cutoff=0.8) if names else []
    return files[near[0]] if near else None


def _pixmap_file(path, size):
    """A user's icon as it is, fitted into the square with its proportions kept and no tile behind it (the user's choice, 2026-11-01)."""
    img = QImage(path).convertToFormat(QImage.Format.Format_ARGB32)
    if img.isNull():
        return None
    out = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    out.fill(Qt.GlobalColor.transparent)
    p = QPainter(out)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    scale = min(size / img.width(), size / img.height())
    w, h = img.width() * scale, img.height() * scale
    p.drawImage(QRectF((size - w) / 2, (size - h) / 2, w, h), img)
    p.end()
    return QPixmap.fromImage(out)


def vendor_source(vendor):
    """Where a vendor's mark comes from: 'file' (the user's folder), 'mark' (a maker's own mark built in) or 'letters'."""
    from core import vendors
    fam = vendors.family(vendor or "")
    if vendor_file(fam):
        return "file"
    return "mark" if fam in VENDOR_PATHS else "letters"


def forget_vendor_icons():
    """The folder or its files changed: the marks are read again next time."""
    for k in [k for k in _cache if k.startswith("vendor:")]:
        del _cache[k]


def vendor_icon(vendor):
    """The mark of a device's maker, by its vendor key ('cisco', 'unifi_network'...): the user's own file when the folder has one,
    else the maker's mark built in, else two letters on a tile."""
    import os
    from core import vendors
    fam = vendors.family(vendor or "")
    path = vendor_file(fam)
    try:
        stamp = os.path.getmtime(path) if path else 0
    except OSError:
        stamp = 0
    key = f"vendor:{fam}:{path or ''}:{stamp}"
    if key not in _cache:
        ic = QIcon()
        for size in (16, 24, 28, 36, 48, 64):
            pm = _pixmap_file(path, size) if path else None
            ic.addPixmap(pm if pm is not None else _pixmap_doc(vendor_tile_svg(fam), size))
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
