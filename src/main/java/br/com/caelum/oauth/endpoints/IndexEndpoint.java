package br.com.caelum.oauth.endpoints;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexEndpoint {

	
	@GetMapping(path="/")
	@ResponseBody
	public String index() {
		return "running ...";
	}
	
}
