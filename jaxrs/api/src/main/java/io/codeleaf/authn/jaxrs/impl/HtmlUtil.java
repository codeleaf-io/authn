package io.codeleaf.authn.jaxrs.impl;

import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class HtmlUtil {

    private HtmlUtil() {
    }

    public static String urlDecode(String urlEncodedString) {
        try {
            return URLDecoder.decode(urlEncodedString, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException cause) {
            throw new InternalError(cause);
        }
    }

    public static String urlEncode(String string) {
        try {
            return URLEncoder.encode(string, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException cause) {
            throw new InternalError(cause);
        }
    }

    public static String htmlEncode(String source) {
        return source
                .replaceAll("&", "&amp;")
                .replaceAll("\"", "&quot;")
                .replaceAll("'", "&#39;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;");
    }

    public static Map<String, String> decodeForm(String formBody) {
        Map<String, String> formFields = new LinkedHashMap<>();
        for (String field : formBody.split("&")) {
            String[] parts = field.split("=");
            if (parts.length != 2) {
                System.err.println("Invalid entry in form data: " + field);
            } else {
                formFields.put(HtmlUtil.urlDecode(parts[0]), HtmlUtil.urlDecode(parts[1]));
            }
        }
        return formFields;
    }

    public static Map<String, String> decodeForm(InputStream formBody) throws IOException {
        return decodeForm(inputStreamToString(formBody));
    }

    private static String inputStreamToString(InputStream is) throws IOException {
        final int bufferSize = 1024;
        final char[] buffer = new char[bufferSize];
        final StringBuilder out = new StringBuilder();
        try (Reader in = new InputStreamReader(is, StandardCharsets.UTF_8)) {
            for (; ; ) {
                int rsz = in.read(buffer, 0, buffer.length);
                if (rsz < 0)
                    break;
                out.append(buffer, 0, rsz);
            }
            return out.toString();
        }
    }
}
