package org.ssor.boss.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;

/**
 * A filter for authorizing users when they attempt to access a resource.
 * @author John Christman
 */
@Slf4j
public class VerificationFilter extends BasicAuthenticationFilter
{
  public VerificationFilter(AuthenticationManager authMgr)
  {
    super(authMgr);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws
      IOException, ServletException
  {
    final var header = request.getHeader("Authorization");
    try
    {
      if (header != null && header.startsWith("Bearer"))
      {
        final var authToken = getAuthenticationToken(header, request);
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }

      chain.doFilter(request, response);
    }
    catch (TokenExpiredException tee)
    {
      log.debug("Verification failed");
      log.debug("Token expired");
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.getWriter().write("{\"error\":\"token expired\"}");
    }
  }

  private UsernamePasswordAuthenticationToken getAuthenticationToken(String token, HttpServletRequest request)
  {
    final var jwt = JWT.require(Algorithm.HMAC512("BossOrphans")).build()
                       .verify(token.replace("Bearer ", ""));
    final var subject = jwt.getSubject();
    if (subject == null)
    {
      log.debug("No subject in token.");
      return null;
    }

    final var userId = jwt.getClaim("userId").asInt();
    final var path = request.getServletPath();
    if (path.matches("/.*?\\d+"))
    {
      // Cut the end of the path off.
      final var endpointId = path.substring(path.lastIndexOf('/') + 1);
      final var idValue = Integer.parseInt(endpointId);
      if (userId != idValue)
        // Force failure on endpoints that don't match the user id.
        return new UsernamePasswordAuthenticationToken(null, null, null);
    }

    final var authorities = jwt.getClaim("authorities").asList(String.class).stream().map(SimpleGrantedAuthority::new)
                               .collect(Collectors.toList());
    log.debug("Authority: " + authorities);
    final var username = jwt.getClaim("username").asString();
    final var password = jwt.getClaim("password").asString();
    return new UsernamePasswordAuthenticationToken(username, password, authorities);
  }
}
