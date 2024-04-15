/*
    This Yara ruleset is under the BSD 3-Clause license (https://opensource.org/licenses/BSD-3-Clause) and
    open to any user or organization, as long as you use it under this license.
*/

/*
    https://asecuritysite.com/forensics/magic
    https://en.wikipedia.org/wiki/List_of_file_signatures
    https://www.garykessler.net/library/file_sigs.html
*/

rule pdf_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "PDF file"

    strings:
        $a = "%PDF-"

    condition:
        $a at 0
}

rule zip_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "ZIP file"

    strings:
        $magic1 = { 50 4b 03 04 }
        $magic2 = { 50 4b 05 06 }
        $magic3 = { 50 4b 07 08 }

    condition:
        ($magic1 at 0) or ($magic2 at 0) or ($magic3 at 0)
}

rule html_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "HTML file"

    strings:
        $a = "<html>"
        $b = "</html>"
        $c = "<!DOCTYPE html>"

        $magic1 = { 3c 68 74 6d 6c 3e }
        $magic2 = { 3c 2f 68 74 6d 6c 3e }
        $magic3 = { 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E }

    condition:
        ($a at 0) or ($b at 0) or ($c at 0) or ($magic1 at 0) or ($magic2 at 0) or ($magic3 at 0)
}

rule email_file : file_type
{
    meta:
        version = "1.0.1"
        author = "Borja Luaces"
        description = "E-mail file"

    strings:
        $a = "Received:"
        $b = "From:"
        $c = "Delivered-To"

        $magic1 = { 52 55 63 65 69 76 65 64 3a }

    condition:
        any of them
}

rule executable_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = " Executable file"

    strings:
        $magic1 = { 4D 5A }

    condition:
        $magic1 at 0
}

rule doc_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "DOC file"

    strings:
        $magic1 = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $magic1 at 0
}

rule xls_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "XLS file"

    strings:
        $magic1 = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $magic1 at 0
}

rule png_file : file_type
{
    meta:
        version = "1.0.1"
        author = "Borja Luaces"
        description = "PNG file"

    strings:
        $a = "PNG"
        $magic1 = { 89 50 4E 47 }

    condition:
        ($a at 0) or ($magic1 at 0)
}

rule gif_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "GIF file"

    strings:
        $a = "GIF89"
        $magic1 = { 47 49 46 38 }

    condition:
        ($a at 0) or ($magic1 at 0)
}

rule bmp_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "BMP file"

    strings:
        $a = "BM"
        $magic1 = { 42 4D }

    condition:
        ($a at 0) or ($magic1 at 0)
}

rule jpg_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "JPEG file"

    strings:
        $magic1 = { FF D8 FF DB }
        $magic2 = { FF D8 FF E0 ?? ?? 4A 46 49 46 00 01 }
        $magic3 = { FF D8 FF E1 ?? ?? 45 78 69 66 00 00 }
        $magic4 = { FF D8 FF E2 }

    condition:
        any of them
}

rule jscript_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "JavaScript"

    strings:
        $a = "<script type=\"text/javascript\">"

    condition:
        any of them
}

rule rtf_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "RTF"

    strings:
        $magic1 = { 7B 5C 72 74 66 31 }

    condition:
        any of them
}

rule rar_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "RAR"

    strings:
        $magic1 = { 52 61 72 21 1A 07 }

    condition:
        any of them
}

rule mso_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "Possible MSO"

    strings:
        $magic1 = { 00 4C 00 }

    condition:
        any of them
}

rule webp_file : file_type
{
    meta:
        version = "1.0.0"
        author = "Borja Luaces"
        description = "webp"

    strings:
        $magic1 = {57 45 42 50}

    condition:
        any of them
}
