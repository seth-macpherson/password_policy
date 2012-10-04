class PasswordPolicy

  MIN_LEN = 0
  MAX_LEN = 64

  def rule_definitions
    # Rule definitions are stored in the Hash @rules
    # Hash key describes rule and is used as the accessor
    # :value      Default value for rule (can be overridden in constructor)
    # :error_msg  Message returned if validation fails
    # :test       Proc returning true if password validates against rule


    @rules[:min_length] = {
      :value      => MIN_LEN,
      :error_msg  => 'Password must be more than #VAL# characters',
      :test       => proc do |password|
        password.length >= @rules[:min_length][:value]
      end
    }

    @rules[:max_length] = {
      :value      => MAX_LEN,
      :error_msg  => 'Password must be less than #VAL# characters',
      :test       => proc do |password|
        password.length <= @rules[:max_length][:value]
      end
    }

    @rules[:min_lowercase_chars] = {
      :value      => MIN_LEN,
      :error_msg  => 'Password must contain at least #VAL# lowercase characters',
      :test       => proc do |password|
        password.scan(/[a-z]/).size >= @rules[:min_lowercase_chars][:value]
      end
    }

    @rules[:min_uppercase_chars] = {
      :value      => MIN_LEN,
      :error_msg  => 'Password must contain at least #VAL# uppercase characters',
      :test       => proc do |password|
        password.scan(/[A-Z]/).size >= @rules[:min_uppercase_chars][:value]
      end
    }

    @rules[:min_numeric_chars] = {
      :value      => MIN_LEN,
      :error_msg  => 'Password must contain at least #VAL# numeric characters',
      :test       => proc do |password|
        password.scan(/[0-9]/).size >= @rules[:min_numeric_chars][:value]
      end
    }

    @rules[:min_special_chars] = {
      :value      => MIN_LEN,
      :error_msg  => 'Password must contain at least #VAL# special characters',
      :test       => proc do |password|
        password.scan(/[\W]/).size >= @rules[:min_special_chars][:value]
      end
    }

    @rules[:max_special_chars] = {
      :value      => MAX_LEN,
      :error_msg  => 'Password must contain no more than #VAL# special characters',
      :test       => proc do |password|
        password.scan(/[\W]/).size <= @rules[:max_special_chars][:value]
      end
    }


    @rules[:max_repeating] = {
      :value      => MAX_LEN,
      :error_msg  => 'Password must contain less than #VAL# repeated characters',
      :test       => proc do |password|
        span = @rules[:max_repeating][:value].to_i - 1
        regex = Regexp.new('([[:print:]])\1{' + span.to_s + ',}')
        password.scan(regex).size == 0
      end
    }

    @rules[:max_numeric_sequential] = {
      :value      => MAX_LEN,
      :error_msg  => 'Password must contain less than #VAL# sequential numeric characters',
      :test       => proc do |password|
        # how many sequential chars does it take to fail 
        span = @rules[:max_numeric_sequential][:value].to_i
        # numeric
        r = (0..9).to_a
        numeric_perms = r.inject([]) {|memo,i|
          tmp = r.rotate!.slice(0, span)
          memo << tmp.join << tmp.reverse.join << (i.to_s * span.to_i)
          memo
          }.join("|")
        numeric_regex = Regexp.new("(" + numeric_perms + ")")
        password.scan(numeric_regex).size == 0
      end                                
    }

    @rules[:max_alpha_sequential] = {
      :value      => MAX_LEN,
      :error_msg  => 'Password must contain less than #VAL# sequential alpha characters',
      :test       => proc do |password|
        # how many sequential chars does it take to fail 
        span = @rules[:max_alpha_sequential][:value].to_i
        # alpha
        r = ('a'..'z').to_a
        alpha_perms = r.inject([]) {|memo,i|
          tmp = r.rotate!.slice(0, span)
          memo << tmp.join << tmp.reverse.join
          memo
          }.join("|")
        alpha_regex = Regexp.new("(" + alpha_perms + ")")
        # evaluate
        password.scan(alpha_regex).size == 0
      end
    }

    @rules[:max_qwerty] = {
      :value      => MAX_LEN,
      :error_msg  => 'Password must not contain #VAL# or more consecutive QWERTY characters.',
      :test       => proc do |password|
        # how many sequential chars does it take to fail 
        span = @rules[:max_qwerty][:value].to_i
        # qwerty 
        r = "qwertyuiopasdfghjklzxcvbnm".split(//)
        qwerty_perms = r.inject([]) {|memo,i|
          tmp = r.rotate!.slice(0, span)
          memo << tmp.join << tmp.reverse.join
          memo
          }.join("|")
        qwerty_regex = Regexp.new("(" + qwerty_perms + ")")
        pp password.scan(qwerty_regex) if password.scan(qwerty_regex).size > 0
        password.scan(qwerty_regex).size == 0

        # TODO: make errors more descriptive
        # if password.scan(qwerty_regex).size > 0
        #   @rules[:max_qwerty][:error_msg] << " The password supplied contained #{password.scan(qwerty_regex).size}."
        # end
      end
    }
    
    @rules[:use_blacklist] = {
      :value      => true,
      :error_msg  => 'Password must not be easy to guess and as common as the one provided.',
      :test       => proc do |password|
        blacklist = "admin|angel|ashley|awesome|bailey|baseball|bitch|career|connect|devil|dick|dragon|Football|fuck|god|iloveyou|jesus|job|jordan|killer|letmein|link|master|michael|monkey|passw0rd|password|pepper|princess|qazwsx|qwerty|sex|shadow|shit|soccer|sunshine|superman|trustno1|work".downcase!
        !blacklist.split("|").include?(password)
      end
    }
  end
end
