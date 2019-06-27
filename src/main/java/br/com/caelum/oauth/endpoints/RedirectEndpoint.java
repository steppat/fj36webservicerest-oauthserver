package br.com.caelum.oauth.endpoints;

import java.util.Map;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Para um exemplo mais próximo de uma situação real, 
 * utilizando autenticação via browser p. ex.,
 * este endpoint deve estar localizado no client
 *
 */
@RestController
@RequestMapping("/redirect")
public class RedirectEndpoint {

//    @Context
//    HttpHeaders httpHeaders;
//    
//    @Context
//    UriInfo uriInfo;

    @GetMapping
    public String redirect(@RequestHeader HttpHeaders httpHeaders, @RequestParam Map<String,String> allRequestParams) {
        
    	JSONObject object = new JSONObject();
        JSONObject headers = new JSONObject(); 
        JSONObject queryParameteres = new JSONObject();
        
        String json = "error!";
        
        
        try {
            for (Map.Entry<String, String> entry : httpHeaders.toSingleValueMap().entrySet()) {
                headers.put(entry.getKey(), entry.getValue());
            }
            
            object.put("headers", headers);
            
            for (Map.Entry<String, String> entry : allRequestParams.entrySet()) {
                queryParameteres.put(entry.getKey(), entry.getValue());
            }
            object.put("queryParameters", queryParameteres);
            
            json = object.toString(4);
            
        } catch (JSONException ex) {
        
        	ex.printStackTrace();
        
        }
        
        return json;
    }
}
