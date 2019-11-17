package net.sesela.sample.spring.saml.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller("sample")
public class SampleController {

	@GetMapping("/")
	public String sample() {
		return "sample";
	}

}
