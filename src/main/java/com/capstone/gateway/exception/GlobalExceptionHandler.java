//package com.capstone.gateway.exception;
//
//import java.util.Map;
//
//import org.springframework.boot.autoconfigure.web.WebProperties.Resources;
//import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
//import org.springframework.boot.web.error.ErrorAttributeOptions;
//import org.springframework.boot.web.reactive.error.ErrorAttributes;
//import org.springframework.context.ApplicationContext;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.HttpStatusCode;
//import org.springframework.http.MediaType;
//import org.springframework.web.reactive.function.BodyInserters;
//import org.springframework.web.reactive.function.server.RequestPredicates;
//import org.springframework.web.reactive.function.server.RouterFunction;
//import org.springframework.web.reactive.function.server.RouterFunctions;
//import org.springframework.web.reactive.function.server.ServerRequest;
//import org.springframework.web.reactive.function.server.ServerResponse;
//import org.springframework.web.server.ResponseStatusException;
//
//import reactor.core.publisher.Mono;
//
//@Configuration
//public class GlobalExceptionHandler extends AbstractErrorWebExceptionHandler {
//
//	public GlobalExceptionHandler(ErrorAttributes errorAttributes, Resources resources,
//			ApplicationContext applicationContext) {
//		super(errorAttributes, resources, applicationContext);
//	}
//
//	@Override
//	protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
//	    return RouterFunctions.route(RequestPredicates.all(), this::renderErrorResponse);
//	}
//
//	private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
//	    ErrorAttributeOptions options = ErrorAttributeOptions.of(ErrorAttributeOptions.Include.MESSAGE);
//	    Map<String, Object> errorPropertiesMap = getErrorAttributes(request, options);
//	    Throwable throwable = getError(request);
//	    HttpStatusCode httpStatus = determineHttpStatus(throwable);
//
//	    errorPropertiesMap.put("status", httpStatus.value());
//	    errorPropertiesMap.remove("error");
//
//	    return ServerResponse.status(httpStatus)
//	      .contentType(MediaType.APPLICATION_JSON_UTF8)
//	      .body(BodyInserters.fromObject(errorPropertiesMap));
//	}
//
//	private HttpStatusCode determineHttpStatus(Throwable throwable) {
//	    if (throwable instanceof ResponseStatusException) {
//	        return ((ResponseStatusException) throwable).getStatusCode();
////	    } else if (throwable instanceof CustomRequestAuthException) {
////	        return HttpStatus.UNAUTHORIZED;
////	    } else if (throwable instanceof RateLimitRequestException) {
////	        return HttpStatus.TOO_MANY_REQUESTS;
//	    } else {
//	        return HttpStatus.INTERNAL_SERVER_ERROR;
//	    }
//	}
//	
//}
