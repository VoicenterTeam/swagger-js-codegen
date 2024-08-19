'use strict';

var fs = require('fs');
var Mustache = require('mustache');
var beautify = require('js-beautify').js_beautify;
var lint = require('jshint').JSHINT;
var _ = require('lodash');

var expose = require('./expose');
var formatter = require('./formatter');
var querier = require('./querier');
var splitter = require('./splitter');
var ts = require('./typescript');

var normalizeName = function(id) {
  return id.replace(/\.|\-|\{|\}|\s/g, '_');
};

var getPathToMethodName = function(opts, m, path){
  if(path === '/' || path === '') {
    return m;
  }

  // clean url path for requests ending with '/'
  var cleanPath = path.replace(/\/$/, '');

  var segments = cleanPath.split('/').slice(1);
  segments = _.transform(segments, function (result, segment) {
    if (segment[0] === '{' && segment[segment.length - 1] === '}') {
      segment = 'by' + segment[1].toUpperCase() + segment.substring(2, segment.length - 1);
    }
    result.push(segment);
  });
  var result = _.camelCase(segments.join('-'));
  return m.toLowerCase() + result[0].toUpperCase() + result.substring(1);
};

var getViewForSwagger3 = function (opts, type) {
  var swagger = opts.swagger;
  var methods = [];
  var authorizedMethods = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'PATCH',
    'COPY',
    'HEAD',
    'OPTIONS',
    'LINK',
    'UNLIK',
    'PURGE',
    'LOCK',
    'UNLOCK',
    'PROPFIND',
  ];

  const securitySchemes =
      swagger.components && swagger.components.securitySchemes
          ? swagger.components.securitySchemes
          : undefined;

  var data = {
    openapi: swagger.openapi,
    isNode: type === 'node' || type === 'javascript',
    isES6: opts.isES6 || type === 'javascript',
    description: swagger.info.description,
    isSecure: typeof securitySchemes !== 'undefined',
    className: opts.className,
    domain:
        swagger.schemes &&
        swagger.schemes.length > 0 &&
        swagger.host &&
        swagger.basePath
            ? swagger.schemes[0] +
            '://' +
            swagger.host +
            swagger.basePath.replace(/\/+$/g, '')
            : '',
    methods: [],
    definitions: [],
  };

  _.forEach(swagger.paths, function (api, path) {
    var globalParams = [];
    /**
     * @param {Object} op - meta data for the request
     * @param {string} m - HTTP method name - eg: 'get', 'post', 'put', 'delete'
     */
    _.forEach(api, function (op, m) {
      if (m.toLowerCase() === 'parameters') {
        globalParams = op;
      }
    });
    _.forEach(api, function (op, m) {
      var M = m.toUpperCase();
      if (M === '' || authorizedMethods.indexOf(M) === -1) {
        return;
      }
      const secureTypes = [];
      if (
          typeof securitySchemes !== 'undefined' ||
          typeof op.security !== 'undefined'
      ) {
        const mergedSecurity = _.flatten(
            _.merge([], swagger.security, op.security).map(function (security) {
              return Object.keys(security);
            }),
        );
        if (securitySchemes) {
          for (const sk in securitySchemes) {
            if (mergedSecurity.includes(sk)) {
              secureTypes.push(securitySchemes[sk].type);
            }
          }
        }
      }
      var methodName = op.operationId
          ? normalizeName(op.operationId)
          : getPathToMethodName(opts, m, path);
      // Make sure the method name is unique
      if (methods.indexOf(methodName) !== -1) {
        var i = 1;
        while (true) {
          if (methods.indexOf(methodName + '_' + i) !== -1) {
            i++;
          } else {
            methodName = methodName + '_' + i;
            break;
          }
        }
      }

      methods.push(methodName);

      var method = {
        path: path,
        className: opts.className,
        methodName: methodName,
        method: M,
        isGET: M === 'GET',
        isPOST: M === 'POST',
        isFormMethod: false,
        summary: op.description || op.summary,
        externalDocs: op.externalDocs,
        isSecure: swagger.security !== undefined || op.security !== undefined,
        isSecureToken: secureTypes.includes('oauth2'),
        isSecureApiKey: secureTypes.includes('apiKey'),
        isSecureBasic: secureTypes.includes('basic'),
        parameters: [],
        headers: [],
      };
      if (opts.multiple) {
        method.destination = op.tags[0].toLowerCase();
      }
      if (method.isSecure && method.isSecureToken) {
        data.isSecureToken = method.isSecureToken;
      }
      if (method.isSecure && method.isSecureApiKey) {
        data.isSecureApiKey = method.isSecureApiKey;
        data.apiKeyHeaderName = (
            Object.values(swagger.components.securitySchemes).find(
                (i) => i.type === 'apiKey',
            ) || { name: 'X-API-Key' }
        ).name;
      }
      if (method.isSecure && method.isSecureBasic) {
        data.isSecureBasic = method.isSecureBasic;
      }

      // @TODO rewrite for OA3 - need an example for parameters
      var params = [];
      if (_.isArray(op.parameters)) {
        params = op.parameters;
      }
      params = params.concat(globalParams);

      var hasBody = false;
      var hasExtraHeader = false;

      if (_.isObject(op.requestBody)) {
        hasBody = true;
        const headerKeys = Object.keys(op.requestBody.content);
        if (headerKeys.length > 0) {
          // selecting only first found header (not supporting multiple content types in request)
          const firstHeaderContentType = headerKeys[0];
          const newParam = {
            in: opts.requestBodyParameterName || 'body',
            name: op.requestBody['x-method-name'],
            description: op.requestBody.description,
            ...op.requestBody.content[firstHeaderContentType],
          };
          if (firstHeaderContentType === 'multipart/form-data') {
            newParam.isFormParameter = true;
          } else if (firstHeaderContentType === 'application/json') {
            newParam.isBodyParameter = true;
          } else if (
              firstHeaderContentType === 'application/x-www-form-urlencoded'
          ) {
            hasBody = false;
          }
          params.push(newParam);

          method.headers.push({
            name: 'Content-Type',
            value: firstHeaderContentType,
          });
          if (firstHeaderContentType === 'multipart/form-data') {
            method.isFormMethod = true;
          }
        }
      }

      var hasAnyRequired = false;
      _.forEach(params, function (parameter) {
        //Ignore parameters which contain the x-exclude-from-bindings extension
        if (parameter['x-exclude-from-bindings'] === true) {
          return;
        }

        // Ignore headers which are injected by proxies & app servers
        // eg: https://cloud.google.com/appengine/docs/go/requests#Go_Request_headers
        if (parameter['x-proxy-header'] && !data.isNode) {
          return;
        }
        if (_.isString(parameter.$ref)) {
          var segments = parameter.$ref.split('/');
          parameter =
              swagger.components.parameters[
                  segments.length === 1 ? segments[0] : segments[3]
                  ];
        }
        parameter.camelCaseName = _.camelCase(parameter.name);
        if (parameter.enum && parameter.enum.length === 1) {
          parameter.isSingleton = true;
          parameter.singleton = parameter.enum[0];
        }
        if (parameter.in === 'path') {
          parameter.isPathParameter = true;
        } else if (parameter.in === 'query') {
          if (parameter['x-name-pattern']) {
            parameter.isPatternType = true;
          }
          parameter.pattern = parameter['x-name-pattern'];
          parameter.isQueryParameter = true;
        } else if (parameter.in === 'header') {
          parameter.isHeaderParameter = true;
          hasExtraHeader = true;
        } else if (parameter.in === 'formData') {
          parameter.isFormParameter = true;
        }
        if (parameter.style === 'pipeDelimited') {
          parameter.transformOperation = 'joinUsingPipes';
        }
        parameter.tsType = ts.convertType(parameter, swagger);
        parameter.default =
            parameter.schema && parameter.schema.default
                ? parameter.schema.default
                : undefined;

        parameter.defaultSerialized = JSON.stringify(parameter.default);

        parameter.cardinality = parameter.required ? '' : '?';

        if (parameter.required && parameter.in !== 'path') {
          hasAnyRequired = true;
        }
        method.parameters.push(parameter);
      });

      method.defaultParam = hasAnyRequired ? '' : ' = {}';
      method.hasExtraHeader = hasExtraHeader;
      method.hasBody = hasBody;
      method.responses = op.responses;
      method.successResponses = [];
      const responseHeaders = {};
      _.forEach(method.responses, (response, statusCode) => {
        const content = response.content;
        _.forEach(content, (schema, contentType) => {
          responseHeaders[contentType] = null;
          if (statusCode === '200' || statusCode === '201') {
            method.successResponses.push({
              tsType: ts.convertType(schema, swagger),
            });
          }
        });
      });
      Object.keys(responseHeaders).forEach((contentType) => {
        method.headers.push({
          name: 'Accept',
          value: contentType,
        });
      });
      if (method.successResponses.length > 0) {
        method.successResponses[method.successResponses.length - 1].last = true;
      }
      data.methods.push(method);
    });
  });

  const definitions =
      swagger.components && swagger.components.schemas
          ? swagger.components.schemas
          : [];

  _.forEach(definitions, function (definition, name) {
    data.definitions.push({
      name: name,
      description: definition.description,
      tsType: ts.convertType(definition, swagger),
    });
  });

  return data;
}

var getViewForSwagger2 = function(opts, type){
  var swagger = opts.swagger;
  var methods = [];
  var authorizedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'COPY', 'HEAD', 'OPTIONS', 'LINK', 'UNLIK', 'PURGE', 'LOCK', 'UNLOCK', 'PROPFIND'];
  var data = {
    isNode: type === 'node' || type === 'react',
    isES6: opts.isES6 || type === 'react',
    description: swagger.info.description,
    isSecure: swagger.securityDefinitions !== undefined,
    moduleName: opts.moduleName,
    className: opts.className,
    imports: opts.imports,
    domain: (swagger.schemes && swagger.schemes.length > 0 && swagger.host && swagger.basePath) ? swagger.schemes[0] + '://' + swagger.host + swagger.basePath.replace(/\/+$/g,'') : '',
    methods: [],
    definitions: []
  };

  _.forEach(swagger.paths, function(api, path) {
    var globalParams = [];
    /**
     * @param {Object} op - meta data for the request
     * @param {string} m - HTTP method name - eg: 'get', 'post', 'put', 'delete'
     */
    _.forEach(api, function(op, m) {
      if (m.toLowerCase() === 'parameters') {
        globalParams = op;
      }
    });
    _.forEach(api, function(op, m) {
      var M = m.toUpperCase();
      if (M === '' || authorizedMethods.indexOf(M) === -1) {
        return;
      }
      var secureTypes = [];
      if (swagger.securityDefinitions !== undefined || op.security !== undefined) {
        var mergedSecurity = _.merge([], swagger.security, op.security).map(function(security) {
          return Object.keys(security);
        });
        if (swagger.securityDefinitions) {
          for (var sk in swagger.securityDefinitions) {
            if (mergedSecurity.join(',').indexOf(sk) !== -1) {
              secureTypes.push(swagger.securityDefinitions[sk].type);
            }
          }
        }
      }

      var methodName = (op.operationId ? normalizeName(op.operationId) : getPathToMethodName(opts, m, path));

      // Make sure the method name is unique
      if (methods.indexOf(methodName) !== -1) {
        var i = 1;
        while (true) {
          if (methods.indexOf(methodName + '_' + i) !== -1) {
            i++;
          } else {
            methodName = methodName + '_' + i;
            break;
          }
        }
      }
      methods.push(methodName);

      var method = {
        path: path,
        className: opts.className,
        methodName: methodName,
        method: M,
        isGET: M === 'GET',
        isPOST: M === 'POST',
        summary: op.description || op.summary,
        externalDocs: op.externalDocs,
        isSecure: swagger.security !== undefined || op.security !== undefined,
        isSecureToken: secureTypes.indexOf('oauth2') !== -1,
        isSecureApiKey: secureTypes.indexOf('apiKey') !== -1,
        isSecureBasic: secureTypes.indexOf('basic') !== -1,
        parameters: [],
        headers: [],
      };

      // add 'destination' field if 'multiple: true'
      if (opts.multiple) {
        method.destination = op.tags[0].toLowerCase();
      }

      // add 'responses' field, that contains schemas and descriptions
      method.responses = op.responses;

      if(method.isSecure && method.isSecureToken) {
        data.isSecureToken = method.isSecureToken;
      }
      if(method.isSecure && method.isSecureApiKey) {
        data.isSecureApiKey = method.isSecureApiKey;
      }
      if(method.isSecure && method.isSecureBasic) {
        data.isSecureBasic = method.isSecureBasic;
      }
      var produces = op.produces || swagger.produces;
      if (produces) {
        method.headers.push({
          name: 'Accept',
          value: `'${produces.map(function(value) { return value; }).join(', ')}'`,
        });
      }

      var consumes = op.consumes || swagger.consumes;
      if(consumes) {
        method.headers.push({name: 'Content-Type', value: '\'' + consumes + '\'' });
      }

      var params = [];
      if(_.isArray(op.parameters)) {
        params = op.parameters;
      }
      params = params.concat(globalParams);
      _.forEach(params, function(parameter) {
        //Ignore parameters which contain the x-exclude-from-bindings extension
        if(parameter['x-exclude-from-bindings'] === true) {
          return;
        }

        // Ignore headers which are injected by proxies & app servers
        // eg: https://cloud.google.com/appengine/docs/go/requests#Go_Request_headers
        if (parameter['x-proxy-header'] && !data.isNode) {
          return;
        }
        if (_.isString(parameter.$ref)) {
          var segments = parameter.$ref.split('/');
          parameter = swagger.parameters[segments.length === 1 ? segments[0] : segments[2] ];
        }
        parameter.camelCaseName = _.camelCase(parameter.name);
        if(parameter.enum && parameter.enum.length === 1) {
          parameter.isSingleton = true;
          parameter.singleton = parameter.enum[0];
        }
        if(parameter.in === 'body'){
          parameter.isBodyParameter = true;
        } else if(parameter.in === 'path'){
          parameter.isPathParameter = true;
        } else if(parameter.in === 'query'){
          if(parameter['x-name-pattern']){
            parameter.isPatternType = true;
            parameter.pattern = parameter['x-name-pattern'];
          }
          parameter.isQueryParameter = true;
        } else if(parameter.in === 'header'){
          parameter.isHeaderParameter = true;
        } else if(parameter.in === 'formData'){
          parameter.isFormParameter = true;
        }
        parameter.tsType = ts.convertType(parameter);
        parameter.cardinality = parameter.required ? '' : '?';
        method.parameters.push(parameter);
      });
      data.methods.push(method);
    });
  });

  _.forEach(swagger.definitions, function(definition, name) {
    data.definitions.push({
      name: name,
      description: definition.description,
      tsType: ts.convertType(definition, swagger)
    });
  });

  return data;
};

var getViewForSwagger1 = function(opts, type){
  var swagger = opts.swagger;
  var data = {
    isNode: type === 'node' || type === 'react',
    isES6: opts.isES6 || type === 'react',
    description: swagger.description,
    moduleName: opts.moduleName,
    className: opts.className,
    domain: swagger.basePath ? swagger.basePath : '',
    methods: []
  };
  swagger.apis.forEach(function(api){
    api.operations.forEach(function(op){
      if (op.method === 'OPTIONS') {
        return;
      }
      var method = {
        path: api.path,
        className: opts.className,
        methodName: op.nickname,
        method: op.method,
        isGET: op.method === 'GET',
        isPOST: op.method.toUpperCase() === 'POST',
        summary: op.summary,
        parameters: op.parameters,
        headers: []
      };

      if(op.produces) {
        var headers = [];
        headers.value = [];
        headers.name = 'Accept';
        headers.value.push(op.produces.map(function(value) { return '\'' + value + '\''; }).join(', '));
        method.headers.push(headers);
      }

      op.parameters = op.parameters ? op.parameters : [];
      op.parameters.forEach(function(parameter) {
        parameter.camelCaseName = _.camelCase(parameter.name);
        if(parameter.enum && parameter.enum.length === 1) {
          parameter.isSingleton = true;
          parameter.singleton = parameter.enum[0];
        }
        if(parameter.paramType === 'body'){
          parameter.isBodyParameter = true;
        } else if(parameter.paramType === 'path'){
          parameter.isPathParameter = true;
        } else if(parameter.paramType === 'query'){
          if(parameter['x-name-pattern']){
            parameter.isPatternType = true;
            parameter.pattern = parameter['x-name-pattern'];
          }
          parameter.isQueryParameter = true;
        } else if(parameter.paramType === 'header'){
          parameter.isHeaderParameter = true;
        } else if(parameter.paramType === 'form'){
          parameter.isFormParameter = true;
        }
      });
      data.methods.push(method);
    });
  });
  return data;
};

/**
 * Generate code based on the input file
 * @param options <OBJECT> - options for the file generation
 * @param type <STRING> - type of code / file to be generated (angular, custom, node, react, typescript)
 * @returns {*}
 */
var getCode = function(options, type) {
  // check 'multiple' & all of the required parameters
  const opts = _.cloneDeep(options);
  if (options.multiple) {
    if (!options.className) {
      throw new Error('Missing the class name!');
    }
    if (!options.swagger) {
      throw new Error('Missing the Swagger JSON!');
    }
    if (!options.path) {
      throw new Error('Missing the destination path!');
    }
    if (!options.controllersDirName) {
      opts.controllersDirName = 'routes_generated';
      console.log('> swagger-js-codegen @ Controllers directory name not provided, using \'routes_generated\' as a default!');
    }
    if (!options.definitionsDirName) {
      opts.definitionsDirName = 'definitions_generated';
      console.log('> swagger-js-codegen @ Definitions directory name not provided, using \'definitions_generated\' as a default!');
    }
  }

  // For Swagger Specification version 2.0 value of field 'swagger' must be a string '2.0'
  var swaggerView;

  switch (opts.swagger.swagger || opts.swagger.openapi) {
    case '2.0':
      swaggerView = getViewForSwagger2(opts, type);
      break;
    case '3.0.3':
      swaggerView = getViewForSwagger3(opts, type);
      break;
    default:
      swaggerView = getViewForSwagger1(opts, type);
      break;
  }

  // format the default responses for the APIs, add objects for the load
  var formatted = formatter.format(swaggerView);

  // create definitions
  expose(opts.swagger.definitions || opts.swagger.components.schemas, formatted.methods, opts.path, opts.definitionsDirName);
  // add all of the necessary query options
  var data = querier(formatted);

  if (type === 'custom') {
    if (!_.isObject(opts.template) || !_.isString(opts.template.class)  || !_.isString(opts.template.method)) {
      throw new Error('Unprovided custom template. Please use the following template: template: { class: "...", method: "...", request: "..." }');
    }
  } else {
    if (!_.isObject(opts.template)) {
      opts.template = {};
    }
    var templates = __dirname + '/../templates/';

    // choose templates based on the 'multiple' option TODO: Typescript support?
    if (opts.multiple) {
      opts.template.class = fs.readFileSync(templates + 'multi-class.mustache', 'utf-8');
      opts.template.method = fs.readFileSync(templates + 'multi-method.mustache', 'utf-8');
    } else {
      opts.template.class = opts.template.class || fs.readFileSync(templates + type + '-class.mustache', 'utf-8');
      opts.template.method = opts.template.method || fs.readFileSync(templates + (type === 'typescript' ? 'typescript-' : '') + 'method.mustache', 'utf-8');
    }
    if (type === 'typescript') {
      opts.template.type = opts.template.type || fs.readFileSync(templates + 'type.mustache', 'utf-8');
    }
  }

  if (opts.mustache) {
    _.assign(data, opts.mustache);
  }

  var source = Mustache.render(opts.template.class, data, opts.template);
  var lintOptions = {
    node: type === 'node' || type === 'custom',
    browser: type === 'angular' || type === 'custom' || type === 'react',
    undef: true,
    strict: true,
    trailing: true,
    smarttabs: true,
    maxerr: 99999
  };
  if (opts.esnext) {
    lintOptions.esnext = true;
  }

  if(type === 'typescript') {
    opts.lint = false;
  }

  if (opts.lint === undefined || opts.lint === true) {
    lint(source, lintOptions);
    lint.errors.forEach(function(error) {
      if (error.code[0] === 'E') {
        throw new Error(error.reason + ' in ' + error.evidence + ' (' + error.code + ')');
      }
    });
  }
  if (opts.multiple) {
    return splitter.split(beautify(source, {
      indent_size: 2,
      max_preserve_newlines: 2
    }), opts.className, opts.path, opts.controllersDirName);
  }
  if (opts.beautify === undefined || opts.beautify === true) {
    return beautify(source, { indent_size: 4, max_preserve_newlines: 2 });
  } else {
    return source;
  }
};

exports.CodeGen = {
  getTypescriptCode: function(opts){
    if (opts.swagger.swagger !== '2.0') {
      throw 'Typescript is only supported for Swagger 2.0 specs.';
    }
    return getCode(opts, 'typescript');
  },
  getAngularCode: function(opts){
    return getCode(opts, 'angular');
  },
  getNodeCode: function(opts){
    return getCode(opts, 'node');
  },
  getReactCode: function(opts){
    return getCode(opts, 'react');
  },
  getCustomCode: function(opts){
    return getCode(opts, 'custom');
  }
};
