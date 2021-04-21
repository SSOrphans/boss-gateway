package org.ssor.boss.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RootController
{
  @GetMapping("/")
  public String getRoot()
  {
    return "<h1>Hello, World!</h1>";
  }

  @GetMapping("/sora")
  public String getSoraPage()
  {
    return "<h1>Hello, Sora!</h1>";
  }
}
