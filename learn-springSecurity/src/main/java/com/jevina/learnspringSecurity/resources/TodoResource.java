package com.jevina.learnspringSecurity.resources;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class TodoResource{
	
	private Logger logger = LoggerFactory.getLogger(getClass());


	private static final List<Todo> TODOS_LIST = 
			List.of(new Todo("jevina", "Learn AWS"),
					new Todo("jevina", "Get AWS Certified"));
	
	@GetMapping("/todos")
	public List<Todo> retrieveAllTodos(){
		return TODOS_LIST;
		}
	
	@GetMapping("/users/{username}/todos")
	//@PreAuthorize("hasRole('USER') and '#username' == authentication.principal.username") 		//#username isn't working
	@PreAuthorize("hasRole('USER') and 'jevina' == authentication.principal.username") 				//shows result only if authenticated username matches
	@PostAuthorize("returnObject.username == 'jevina'")						//the return object must contain username same , else will show error
	@RolesAllowed({"ADMIN","USER"})
	@Secured({"ROLE_ADMIN","ROLE_USER"})
	public Todo retrieveTodosForSpecificUser(@PathVariable("username") String username) {
		logger.info("Auth name : {}",username);
		return TODOS_LIST.get(0);
	}
	
	@PostMapping("/users/{username}/todos")
	public void createTodoForSpecificUser(@PathVariable("username") String username
			, @RequestBody Todo todo) {
		logger.info("Create {} for {}", todo, username);
	}
}

record Todo (String username, String description) {}
