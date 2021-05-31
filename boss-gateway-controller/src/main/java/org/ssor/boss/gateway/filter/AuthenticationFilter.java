package org.ssor.boss.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.ssor.boss.core.entity.User;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * A filter for authenticating users when they attempt to login.
 * @author John Christman
 */
@Slf4j
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter
{
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  private static class AuthDetails
  {
    private String username;
    private String password;
  }

  public AuthenticationFilter(AuthenticationManager authMgr)
  {
    super(authMgr);
    setFilterProcessesUrl("/login");
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException
  {
    log.debug("Authentication Attempt");
    try
    {
      final var authMgr = getAuthenticationManager();
      final var authDtl = new ObjectMapper().readValue(request.getInputStream(), AuthDetails.class);
      log.debug("AuthDetails: " + authDtl.toString());
      return authMgr.authenticate(new UsernamePasswordAuthenticationToken(authDtl.getUsername(),
                                                                          authDtl.getPassword(),
                                                                          Collections.emptySet()));
    }
    catch (final IOException ioe)
    {
      log.debug(ioe.getMessage());
      return new UsernamePasswordAuthenticationToken(null, null, null);
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authResult) throws IOException, ServletException
  {
    log.debug("Authentication successful");
    final var date = new Date(Instant.now().plusSeconds(8640000).toEpochMilli());
    final var user = (User)authResult.getPrincipal();
    log.debug("Principal: " + user.toString());
    final var authorities = user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList());
    final var jwt = JWT.create()
                       .withSubject(user.getUsername())
                       .withIssuer("ssor-boss")
                       .withClaim("userId", user.getId())
                       .withClaim("username", user.getUsername())
                       .withClaim("password", user.getPassword())
                       .withClaim("authorities", authorities)
                       .withExpiresAt(date)
                       .sign(Algorithm.HMAC512("BossOrphans"));
    log.debug("Created JWT: " + jwt);
    response.getWriter().write("{ \"token\": \"" + jwt + "\" }");
//    response.addHeader("Token", "Bearer " + jwt); // Set the token to be used, safer than placing it in the body.
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException
  {
    log.debug("Authentication failed");
    super.unsuccessfulAuthentication(request, response, failed);
  }
}
