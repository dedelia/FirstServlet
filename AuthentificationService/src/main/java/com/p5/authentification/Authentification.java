package com.p5.authentification;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Created by dtristu on 27.11.2016.
 */
public class Authentification extends HttpServlet implements Filter{

    Map<String,String> tokens = new HashMap<String, String>();


    public void init(FilterConfig filterConfig) throws ServletException {

        tokens.put("device1","0001");
        tokens.put("device2","0010");
        tokens.put("device3","0011");

    }


    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            StringTokenizer st = new StringTokenizer(authHeader);
            if (st.hasMoreTokens()) {
                String basic = st.nextToken();

                if (basic.equalsIgnoreCase("Basic")) {
                    try {
                        String credentials = st.nextToken();

                        int p = credentials.indexOf(":");
                        if (p != -1) {
                            String device = credentials.substring(0, p).trim();
                            String token = credentials.substring(p + 1).trim();

                            Iterator it = tokens.entrySet().iterator();

                            while (it.hasNext()) {
                                Map.Entry currentDevice = (Map.Entry)it.next();
                                if(!currentDevice.getKey().toString().equals(device))
                                    if(!currentDevice.getValue().toString().equals(token))
                                        unauthorized(response, "Bad credentials");
                                it.remove(); // avoids a ConcurrentModificationException
                            }

                            filterChain.doFilter(servletRequest, servletResponse);
                        } else {
                            unauthorized(response, "Invalid authentication token");
                        }
                    } catch (UnsupportedEncodingException e) {
                        throw new Error("Couldn't retrieve authentication", e);
                    }
                }
            }
        } else {
            unauthorized(response);
        }


    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.sendError(401, message);
    }

    private void unauthorized(HttpServletResponse response) throws IOException {
        unauthorized(response, "Unauthorized");
    }
}
