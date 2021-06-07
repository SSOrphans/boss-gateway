package org.ssor.boss.gateway.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.ssor.boss.core.service.UserService;
import org.ssor.boss.gateway.filter.AuthenticationFilter;
import org.ssor.boss.gateway.filter.VerificationFilter;
import java.util.List;

@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter
{
  // TODO:
  //   Set up a profile for H2 and use this to check if we're using that profile.
  private final Environment environment;
  private final PasswordEncoder passwordEncoder;
  private final UserService userService;

  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider()
  {
    final var provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder);
    provider.setUserDetailsService(userService);
    return provider;
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource()
  {
    final var configuration = new CorsConfiguration();
    configuration.setAllowedMethods(List.of(
        HttpMethod.GET.name(),
        HttpMethod.PUT.name(),
        HttpMethod.POST.name(),
        HttpMethod.DELETE.name()
    ));

    final var source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration.applyPermitDefaultValues());
    return source;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception
  {
    auth.authenticationProvider(daoAuthenticationProvider());
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception
  {
    // TODO:
    //   Conditionally set this when using H2.
    // H2 only!
    http.authorizeRequests().antMatchers("/h2-console/**").permitAll();
    http.headers().frameOptions().disable();
    // H2 only!

    http.cors()
        .configurationSource(corsConfigurationSource())
        .and()
        .csrf().disable()
        .authorizeRequests()
        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
        .requestMatchers(CorsUtils::isCorsRequest).permitAll()
        .antMatchers().permitAll()
        .antMatchers(HttpMethod.GET, "/api/v*/users/{\\d+}").hasAnyAuthority("USER_DEFAULT", "USER_VENDOR")
        .antMatchers(HttpMethod.PUT, "/api/v*/users/{\\d+}").hasAuthority("USER_DEFAULT")
        .antMatchers(HttpMethod.DELETE, "/api/v*/users/{\\d+}").hasAuthority("USER_DEFAULT")
        .antMatchers("/public/**").permitAll()
        .antMatchers("/*.ico").permitAll()
        .antMatchers("/").permitAll()
        .anyRequest().authenticated()
        .and()
        .addFilter(new AuthenticationFilter(authenticationManager()))
        .addFilter(new VerificationFilter(authenticationManager()))
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
  }
}
